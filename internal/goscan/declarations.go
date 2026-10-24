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
			component := tlsConfiguration(pkg, literal, &evidence)
			ref := result.Add(component, evidence, parent)
			result.DependOn(ref, providers[path])
			return true
		})
	}
}

func tlsConfiguration(pkg *packages.Package, literal *ast.CompositeLit, evidence *inventory.Evidence) cdx.Component {
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
		var label, text string
		known := false
		switch field.Name {
		case "MinVersion", "MaxVersion":
			label = "tls.min-version"
			if field.Name == "MaxVersion" {
				label = "tls.max-version"
			}
			if value != nil {
				if number, ok := constant.Uint64Val(value); ok && number <= 65535 {
					known = true
					if number == 0 {
						text = "Go runtime default"
					} else {
						text = probe.TLSVersion(uint16(number))
					}
				}
			}
		case "InsecureSkipVerify":
			label = "tls.insecure-skip-verify"
			if value != nil && value.Kind() == constant.Bool {
				text, known = value.ExactString(), true
			}
		case "ClientAuth":
			label = "tls.client-auth"
			if value != nil {
				if number, ok := constant.Int64Val(value); ok && number >= 0 && number <= int64(tls.RequireAndVerifyClientCert) {
					text, known = tls.ClientAuthType(number).String(), true
				}
			}
		default:
			continue
		}
		if known {
			inventory.Property(&component, label, text)
		} else {
			evidence.Unresolved = append(evidence.Unresolved, label)
		}
	}
	return component
}

func declarationText(values *declarationValues, expression ast.Expr) (string, bool) {
	value := values.scalar(expression)
	if value == nil {
		return "", false
	}
	if value.Kind() == constant.String {
		return constant.StringVal(value), true
	}
	return value.ExactString(), true
}

func declarationDuration(values *declarationValues, expression ast.Expr) (string, bool) {
	fields := declarationFields(values.literal(expression))
	value := values.scalar(fields["Duration"])
	if value != nil && value.Kind() == constant.Int {
		if nanos, ok := constant.Int64Val(value); ok {
			return time.Duration(nanos).String(), true
		}
	}
	return "", false
}

func declarationUsages(values *declarationValues, expression ast.Expr) (string, bool) {
	literal := values.literal(expression)
	if literal == nil {
		return "", false
	}
	var usages []string
	for _, element := range literal.Elts {
		value := values.scalar(element)
		if value == nil || value.Kind() != constant.String {
			return "", false
		}
		usages = append(usages, constant.StringVal(value))
	}
	return strings.Join(usages, ", "), true
}

func addDeclarationParameter(component *cdx.Component, evidence *inventory.Evidence, values *declarationValues, name string, expression, declaredExpression ast.Expr, format func(*declarationValues, ast.Expr) (string, bool)) {
	if expression == nil && declaredExpression == nil {
		return
	}
	if exact, known := format(values, expression); known {
		inventory.Property(component, name, exact)
		return
	}
	candidate := *values
	candidate.declared = true
	if declared, known := format(&candidate, declaredExpression); known && values.project != nil {
		if origin := candidate.expression(declaredExpression); origin != nil {
			fact := values.project.fact(name, declared, origin)
			if fact.Location != "" {
				inventory.Property(component, name+":declared", declared)
				evidence.Parameters = append(evidence.Parameters, fact)
				return
			}
		}
	}
	evidence.Unresolved = append(evidence.Unresolved, name)
}

func certificateConfiguration(result *inventory.Result, literal *ast.CompositeLit, values *declarationValues, evidence inventory.Evidence, parent, provider string) {
	fields := declarationFields(literal)
	candidate := *values
	candidate.declared = true
	certificate := operation("cert-manager Certificate configuration", cdx.CryptoAssetTypeCertificate)
	certificate.CryptoProperties.CertificateProperties = &cdx.CertificateProperties{CertificateFormat: "X.509"}
	for _, field := range []struct {
		goName, property string
		format           func(*declarationValues, ast.Expr) (string, bool)
	}{
		{"SecretName", "secret-name", declarationText}, {"CommonName", "common-name", declarationText},
		{"IsCA", "is-ca", declarationText}, {"Duration", "duration", declarationDuration},
		{"RenewBefore", "renew-before", declarationDuration}, {"Usages", "usages", declarationUsages},
	} {
		expression := fields[field.goName]
		addDeclarationParameter(&certificate, &evidence, values, "cert-manager."+field.property, expression, expression, field.format)
	}
	issuerLiteral, candidateIssuerLiteral := values.literal(fields["IssuerRef"]), candidate.literal(fields["IssuerRef"])
	issuer, candidateIssuer := declarationFields(issuerLiteral), declarationFields(candidateIssuerLiteral)
	if fields["IssuerRef"] != nil && issuerLiteral == nil && candidateIssuerLiteral == nil {
		evidence.Unresolved = append(evidence.Unresolved, "cert-manager.issuer")
	}
	for _, field := range []struct{ goName, property string }{
		{"Name", "cert-manager.issuer.name"}, {"Kind", "cert-manager.issuer.kind"}, {"Group", "cert-manager.issuer.group"},
	} {
		addDeclarationParameter(&certificate, &evidence, values, field.property, issuer[field.goName], candidateIssuer[field.goName], declarationText)
	}
	if privateKey := fields["PrivateKey"]; privateKey != nil {
		keyEvidence := evidence
		keyEvidence.Parameters = nil
		keyEvidence.Unresolved = nil
		keyEvidence.Line = values.pkg.Fset.PositionFor(privateKey.Pos(), false).Line
		keyEvidence.Symbol = certManagerPackage + ".CertificatePrivateKey"
		keyRef := certificateKeyConfiguration(result, privateKey, values, keyEvidence, parent, provider)
		certificate.CryptoProperties.CertificateProperties.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{
			{Type: "privateKey", Ref: keyRef},
		}
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
	algorithmName, _ := declarationText(values, fields["Algorithm"])
	if literal == nil && candidateLiteral == nil {
		evidence.Unresolved = append(evidence.Unresolved, "cert-manager.private-key")
	}
	for _, field := range []struct{ goName, property string }{
		{"Algorithm", "cert-manager.key-algorithm"}, {"Size", "cert-manager.key-size"},
		{"Encoding", "cert-manager.key-encoding"}, {"RotationPolicy", "cert-manager.rotation-policy"},
	} {
		addDeclarationParameter(&key, &evidence, values, field.property, fields[field.goName], candidateFields[field.goName], declarationText)
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
