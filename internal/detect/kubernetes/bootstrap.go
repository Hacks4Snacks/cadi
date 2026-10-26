package kubernetes

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"

	"ciphertrail/internal/inventory"

	"go.yaml.in/yaml/v3"
)

func bootstrapResource(api, kind string) bool {
	switch api {
	case "controlplane.cluster.x-k8s.io/v1beta1", "controlplane.cluster.x-k8s.io/v1beta2":
		return kind == "KubeadmControlPlane"
	case "bootstrap.cluster.x-k8s.io/v1beta1", "bootstrap.cluster.x-k8s.io/v1beta2":
		return kind == "KubeadmConfigTemplate" || kind == "KubeadmConfig"
	}
	return false
}

func pureConfiguration(api, kind string) bool {
	if api == "apiserver.config.k8s.io/v1" && kind == "EncryptionConfiguration" {
		return true
	}
	if api == "kubeadm.k8s.io/v1beta3" || api == "kubeadm.k8s.io/v1beta4" {
		return kind == "ClusterConfiguration" || kind == "InitConfiguration" || kind == "JoinConfiguration"
	}
	return false
}

func (r resource) bootstrap(ctx context.Context, node *yaml.Node, kind string) error {
	body, field := node, ""
	var path []string
	switch kind {
	case "KubeadmControlPlane":
		path = []string{"spec", "kubeadmConfigSpec"}
	case "KubeadmConfigTemplate":
		path = []string{"spec", "template", "spec"}
	case "KubeadmConfig":
		path = []string{"spec"}
	}
	for _, part := range path {
		body = fields(body)[part]
		field += "/" + part
		if err := r.mapping(body, "bootstrap configuration"); err != nil {
			return err
		}
	}
	object := fields(body)
	cluster, clusterField := object["clusterConfiguration"], field+"/clusterConfiguration"
	if kind == "ClusterConfiguration" {
		cluster, clusterField = body, field
	}
	var failures error
	if cluster != nil {
		if err := r.mapping(cluster, "clusterConfiguration"); err != nil {
			return err
		}
		failures = errors.Join(failures, r.bootstrapCertificates(cluster, clusterField))
		configuration := fields(cluster)
		for _, component := range []string{"apiServer", "controllerManager", "scheduler"} {
			settings := configuration[component]
			if err := r.mapping(settings, component); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
			failures = errors.Join(failures, r.bootstrapTLS(fields(settings)["extraArgs"],
				clusterField+"/"+component+"/extraArgs", component))
		}
		local := fields(configuration["etcd"])["local"]
		if err := r.mapping(local, "etcd local configuration"); err != nil {
			failures = errors.Join(failures, err)
		} else {
			failures = errors.Join(failures, r.bootstrapTLS(fields(local)["extraArgs"], clusterField+"/etcd/local/extraArgs", "etcd"))
		}
	}
	for _, phase := range []struct{ key, label, kind string }{
		{"initConfiguration", "init kubelet", "InitConfiguration"},
		{"joinConfiguration", "join kubelet", "JoinConfiguration"},
	} {
		configuration, base := object[phase.key], field+"/"+phase.key
		if kind == phase.kind {
			configuration, base = body, field
		}
		if err := r.mapping(configuration, phase.key); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		registration := fields(configuration)["nodeRegistration"]
		if err := r.mapping(registration, "nodeRegistration"); err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		failures = errors.Join(failures, r.bootstrapTLS(fields(registration)["kubeletExtraArgs"],
			base+"/nodeRegistration/kubeletExtraArgs", phase.label))
	}
	failures = errors.Join(failures, r.bootstrapFiles(ctx, object["files"], field+"/files"))
	return failures
}

func (r resource) bootstrapFiles(ctx context.Context, files *yaml.Node, field string) error {
	if files == nil {
		return nil
	}
	if files.Kind != yaml.SequenceNode {
		return r.failure(files, "bootstrap files must be a list")
	}
	var failures error
	for index, file := range files.Content {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		if file.Kind != yaml.MappingNode {
			failures = errors.Join(failures, r.failure(file, "bootstrap file must be an object"))
			continue
		}
		object := fields(file)
		content := object["content"]
		if content == nil {
			continue
		}
		if object["contentFrom"] != nil {
			failures = errors.Join(failures, r.failure(file, "bootstrap file cannot combine content and contentFrom"))
			continue
		}
		path, known, err := configuredText(object["path"])
		if err != nil {
			failures = errors.Join(failures, r.failure(file, "bootstrap file path must be a string"))
			continue
		}
		origin := inventory.EmbeddedContext{File: path}
		if !known {
			origin.Unresolved = []string{"file"}
		}
		if content.Kind != yaml.ScalarNode || content.Tag != "!!str" {
			failures = errors.Join(failures, r.failure(content, "bootstrap file content must be a string"))
			continue
		}
		data := []byte(content.Value)
		encoding, encodingKnown, err := configuredText(object["encoding"])
		if err != nil {
			failures = errors.Join(failures, r.failure(file, "bootstrap file encoding must be a string"))
			continue
		}
		if encodingNode := object["encoding"]; encodingNode != nil && encodingNode.Tag != "!!null" && !encodingKnown {
			r.note(encodingNode, "bootstrap file encoding is unresolved; content was not analyzed")
			continue
		}
		switch encoding {
		case "":
		case "base64":
			data, err = base64.StdEncoding.DecodeString(content.Value)
			if err != nil {
				failures = errors.Join(failures, r.failure(content, "invalid base64 in bootstrap file"))
				continue
			}
		default:
			r.note(file, "bootstrap file encoding is not modeled; content was not analyzed")
			continue
		}
		failures = errors.Join(failures, r.embedded(ctx, data,
			r.at(content, field+"/"+strconv.Itoa(index)+"/content"), origin))
	}
	return failures
}

func (r resource) bootstrapCertificates(node *yaml.Node, field string) error {
	values, unresolved, err := r.parameters(node, []parameter{
		{"caCertificateValidityPeriodDays", "kubeadm.ca-validity-days", intValue},
		{"certificateValidityPeriodDays", "kubeadm.certificate-validity-days", intValue},
		{"caCertificateValidityPeriod", "kubeadm.ca-validity", durationValue},
		{"certificateValidityPeriod", "kubeadm.certificate-validity", durationValue},
		{"encryptionAlgorithm", "kubeadm.encryption-algorithm", configuredText},
	})
	if err != nil || len(values)+len(unresolved) == 0 {
		return err
	}
	evidence := r.at(node, field)
	evidence.Unresolved = unresolved
	keyRef := ""
	algorithmNode := fields(node)["encryptionAlgorithm"]
	algorithm, known, err := configuredText(algorithmNode)
	if err != nil {
		return r.failure(algorithmNode, "kubeadm encryptionAlgorithm must be a string")
	}
	if known {
		var name string
		var size int
		switch algorithm {
		case "RSA-2048":
			name, size = "RSA", 2048
		case "RSA-3072":
			name, size = "RSA", 3072
		case "RSA-4096":
			name, size = "RSA", 4096
		case "ECDSA-P256":
			name, size = "ECDSA", 256
		default:
			r.note(algorithmNode, "kubeadm encryptionAlgorithm is not modeled; no algorithm is inferred")
		}
		if name != "" {
			keyRef = r.result.AddConfiguredPrivateKey("Kubeadm private key configuration", name, size, nil,
				r.at(algorithmNode, field+"/encryptionAlgorithm"), r.parent)
		}
	}
	r.result.Add(inventory.ConfiguredCertificate("Kubeadm certificate configuration", keyRef, values), evidence, r.parent)
	return nil
}
