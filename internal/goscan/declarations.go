package goscan

import (
	"crypto/tls"
	"go/ast"
	"go/constant"
	"go/types"
	"strconv"
	"strings"
	"time"

	"ciphertrail/internal/inventory"
	"ciphertrail/internal/probe"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/tools/go/packages"
)

const certManagerPackage = "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

func scanCryptoDeclarations(result *inventory.Result, root string, pkg *packages.Package, parent string, providers map[string]string, exclusions []string, project *declarationProject) {
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			literalType := pkg.TypesInfo.TypeOf(literal)
			if literalType == nil {
				return true
			}
			named, ok := types.Unalias(literalType).(*types.Named)
			if !ok || named.Obj().Pkg() == nil {
				return true
			}
			position := pkg.Fset.PositionFor(literal.Pos(), false)
			if !inside(root, position.Filename) || sourcePathExcluded(root, position.Filename, exclusions) {
				return true
			}
			path, name := named.Obj().Pkg().Path(), named.Obj().Name()
			evidence := inventory.Evidence{Kind: "configured", Collector: "go",
				Location: relative(root, position.Filename), Line: position.Line, Symbol: path + "." + name}
			if path == certManagerPackage {
				if name != "CertificateSpec" && name != "CertificatePrivateKey" {
					return true
				}
				values := project.resolvers[pkg]
				switch name {
				case "CertificateSpec":
					certificateConfiguration(result, literal, values, evidence, parent, providers[path])
				case "CertificatePrivateKey":
					certificateKeyConfiguration(result, literal, values, evidence, parent, providers[path])
				}
				return true
			}
			if path != "crypto/tls" || name != "Config" {
				return true
			}
			component := tlsConfiguration(pkg, literal)
			ref := result.Add(component, evidence, parent)
			result.DependOn(ref, providers[path])
			return true
		})
	}
}

func tlsConfiguration(pkg *packages.Package, literal *ast.CompositeLit) cdx.Component {
	component := protocol("TLS configuration", cdx.CryptoProtocolTypeTLS)
	for _, element := range literal.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		field, ok := entry.Key.(*ast.Ident)
		if !ok {
			continue
		}
		value := pkg.TypesInfo.Types[entry.Value].Value
		switch field.Name {
		case "MinVersion", "MaxVersion":
			label := "tls.min-version"
			if field.Name == "MaxVersion" {
				label = "tls.max-version"
			}
			text := "unknown"
			if value != nil {
				if number, ok := constant.Uint64Val(value); ok && number <= 65535 {
					if number == 0 {
						text = "Go runtime default"
					} else {
						text = probe.TLSVersion(uint16(number))
					}
				}
			}
			inventory.Property(&component, label, text)
		case "InsecureSkipVerify":
			text := "unknown"
			if value != nil && value.Kind() == constant.Bool {
				text = value.ExactString()
			}
			inventory.Property(&component, "tls.insecure-skip-verify", text)
		case "ClientAuth":
			text := "unknown"
			if value != nil {
				if number, ok := constant.Int64Val(value); ok && number >= 0 && number <= int64(tls.RequireAndVerifyClientCert) {
					text = tls.ClientAuthType(number).String()
				}
			}
			inventory.Property(&component, "tls.client-auth", text)
		}
	}
	inventory.Property(&component, "scope", "struct initializer only; subsequent mutations and runtime defaults are not resolved")
	return component
}

func declarationText(values *declarationValues, expression ast.Expr) string {
	value := values.scalar(expression)
	if value == nil {
		return "unknown"
	}
	if value.Kind() == constant.String {
		return constant.StringVal(value)
	}
	return value.ExactString()
}

func declarationDuration(values *declarationValues, expression ast.Expr) string {
	fields := declarationFields(values.literal(expression))
	value := values.scalar(fields["Duration"])
	if value != nil && value.Kind() == constant.Int {
		if nanos, ok := constant.Int64Val(value); ok {
			return time.Duration(nanos).String()
		}
	}
	return "unknown"
}

func declarationUsages(values *declarationValues, expression ast.Expr) string {
	literal := values.literal(expression)
	if literal == nil {
		return "unknown"
	}
	var usages []string
	for _, element := range literal.Elts {
		value := values.scalar(element)
		if value == nil || value.Kind() != constant.String {
			return "unknown"
		}
		usages = append(usages, constant.StringVal(value))
	}
	return strings.Join(usages, ", ")
}

func addDeclaredParameter(component *cdx.Component, evidence *inventory.Evidence, values *declarationValues, name, exact, declared string, expression ast.Expr) {
	if exact != "unknown" || declared == "unknown" || values.project == nil {
		return
	}
	candidate := *values
	candidate.declared = true
	origin := candidate.expression(expression)
	if origin == nil {
		return
	}
	fact := values.project.fact(name, declared, origin)
	if fact.Location == "" {
		return
	}
	inventory.Property(component, name+":declared", declared)
	evidence.Parameters = append(evidence.Parameters, fact)
}

func certificateConfiguration(result *inventory.Result, literal *ast.CompositeLit, values *declarationValues, evidence inventory.Evidence, parent, provider string) {
	fields := declarationFields(literal)
	candidate := *values
	candidate.declared = true
	certificate := operation("cert-manager Certificate configuration", cdx.CryptoAssetTypeCertificate)
	certificate.CryptoProperties.CertificateProperties = &cdx.CertificateProperties{CertificateFormat: "X.509"}
	inventory.Property(&certificate, "scope", "CertificateSpec declaration; certificate issuance, deployed contents, and runtime use are not established")
	inventory.Property(&certificate, "cert-manager.secret-name", declarationText(values, fields["SecretName"]))
	inventory.Property(&certificate, "cert-manager.common-name", declarationText(values, fields["CommonName"]))
	inventory.Property(&certificate, "cert-manager.is-ca", declarationText(values, fields["IsCA"]))
	inventory.Property(&certificate, "cert-manager.duration", declarationDuration(values, fields["Duration"]))
	inventory.Property(&certificate, "cert-manager.renew-before", declarationDuration(values, fields["RenewBefore"]))
	inventory.Property(&certificate, "cert-manager.usages", declarationUsages(values, fields["Usages"]))
	issuer := declarationFields(values.literal(fields["IssuerRef"]))
	inventory.Property(&certificate, "cert-manager.issuer.name", declarationText(values, issuer["Name"]))
	inventory.Property(&certificate, "cert-manager.issuer.kind", declarationText(values, issuer["Kind"]))
	inventory.Property(&certificate, "cert-manager.issuer.group", declarationText(values, issuer["Group"]))
	addDeclaredParameter(&certificate, &evidence, values, "cert-manager.duration", declarationDuration(values, fields["Duration"]), declarationDuration(&candidate, fields["Duration"]), fields["Duration"])
	addDeclaredParameter(&certificate, &evidence, values, "cert-manager.renew-before", declarationDuration(values, fields["RenewBefore"]), declarationDuration(&candidate, fields["RenewBefore"]), fields["RenewBefore"])
	addDeclaredParameter(&certificate, &evidence, values, "cert-manager.usages", declarationUsages(values, fields["Usages"]), declarationUsages(&candidate, fields["Usages"]), fields["Usages"])
	candidateIssuer := declarationFields(candidate.literal(fields["IssuerRef"]))
	for _, field := range []struct{ goName, property string }{
		{"Name", "cert-manager.issuer.name"}, {"Kind", "cert-manager.issuer.kind"}, {"Group", "cert-manager.issuer.group"},
	} {
		addDeclaredParameter(&certificate, &evidence, values, field.property, declarationText(values, issuer[field.goName]), declarationText(&candidate, candidateIssuer[field.goName]), candidateIssuer[field.goName])
	}
	if privateKey := fields["PrivateKey"]; privateKey != nil {
		keyEvidence := evidence
		keyEvidence.Parameters = nil
		keyEvidence.Line = values.pkg.Fset.PositionFor(privateKey.Pos(), false).Line
		keyEvidence.Symbol = certManagerPackage + ".CertificatePrivateKey"
		keyRef := certificateKeyConfiguration(result, privateKey, values, keyEvidence, parent, provider)
		certificate.CryptoProperties.CertificateProperties.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{
			{Type: "privateKey", Ref: keyRef},
		}
	} else {
		inventory.Property(&certificate, "cert-manager.private-key", "unknown: no explicit private-key configuration")
	}
	ref := result.Add(certificate, evidence, parent)
	result.DependOn(ref, provider)
}

func certificateKeyConfiguration(result *inventory.Result, expression ast.Expr, values *declarationValues, evidence inventory.Evidence, parent, provider string) string {
	literal := values.literal(expression)
	fields := declarationFields(literal)
	candidate := *values
	candidate.declared = true
	candidateLiteral := candidate.literal(expression)
	candidateFields := declarationFields(candidateLiteral)
	key := keyOperation("cert-manager Private key configuration")
	properties := key.CryptoProperties.RelatedCryptoMaterialProperties
	algorithmName := declarationText(values, fields["Algorithm"])
	inventory.Property(&key, "cert-manager.key-algorithm", algorithmName)
	inventory.Property(&key, "cert-manager.key-size", declarationText(values, fields["Size"]))
	inventory.Property(&key, "cert-manager.key-encoding", declarationText(values, fields["Encoding"]))
	inventory.Property(&key, "cert-manager.rotation-policy", declarationText(values, fields["RotationPolicy"]))
	inventory.Property(&key, "scope", "private-key configuration declaration; no key material or generation outcome is observed")
	for _, field := range []struct{ goName, property string }{
		{"Algorithm", "cert-manager.key-algorithm"}, {"Size", "cert-manager.key-size"},
		{"Encoding", "cert-manager.key-encoding"}, {"RotationPolicy", "cert-manager.rotation-policy"},
	} {
		addDeclaredParameter(&key, &evidence, values, field.property, declarationText(values, fields[field.goName]), declarationText(&candidate, candidateFields[field.goName]), candidateFields[field.goName])
	}
	var size int
	value := values.scalar(fields["Size"])
	if value != nil && value.Kind() == constant.Int && integerFits(value, types.Typ[types.Int]) {
		bits, _ := constant.Int64Val(value)
		if bits > 0 && algorithmName != "Ed25519" {
			size = int(bits)
			properties.Size = &size
		}
	}
	var algorithm cdx.Component
	switch algorithmName {
	case "RSA":
		algorithm = inventory.Algorithm(algorithmName, cdx.CryptoPrimitivePKE)
	case "ECDSA":
		algorithm = inventory.Algorithm(algorithmName, cdx.CryptoPrimitiveSignature)
		if size == 256 || size == 384 || size == 521 {
			algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID("P-" + strconv.Itoa(size))
		}
	case "Ed25519":
		algorithm = inventory.Algorithm(algorithmName, cdx.CryptoPrimitiveSignature)
		algorithm.CryptoProperties.AlgorithmProperties.EllipticCurve = inventory.CurveID("Ed25519")
	}
	if algorithm.CryptoProperties != nil {
		if size > 0 {
			algorithm.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = strconv.Itoa(size)
		}
		algorithmRef := result.Add(algorithm, evidence, parent)
		result.DependOn(algorithmRef, provider)
		properties.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: algorithmRef}}
	}
	if literal == nil && candidateLiteral != nil && values.project != nil {
		if owner := values.project.owners[candidateLiteral]; owner != nil {
			position := owner.Fset.PositionFor(candidateLiteral.Pos(), false)
			policyEvidence := inventory.Evidence{Kind: "configured", Collector: "go",
				Location: relative(values.project.root, position.Filename), Line: position.Line,
				Symbol: certManagerPackage + ".CertificatePrivateKey"}
			policyRef := certificateKeyConfiguration(result, candidateLiteral, values, policyEvidence, parent, provider)
			properties.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{{Type: "declaredPolicy", Ref: policyRef}}
		}
	}
	ref := result.Add(key, evidence, parent)
	result.DependOn(ref, provider)
	return ref
}
