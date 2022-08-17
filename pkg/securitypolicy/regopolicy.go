//go:build linux
// +build linux

package securitypolicy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim/internal/guest/spec"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/pkg/errors"

	oci "github.com/opencontainers/runtime-spec/specs-go"
)

//go:embed framework.rego
var FrameworkCode string

//go:embed policy.rego
var PolicyCode string

var CompiledModules *ast.Compiler

func compileFramework(printEnabled bool) (*ast.Compiler, error) {
	if CompiledModules == nil {
		modules := map[string]string{
			"policy.rego":    PolicyCode,
			"framework.rego": FrameworkCode,
		}
		opts := ast.CompileOpts{
			EnablePrintStatements: printEnabled,
		}
		var err error
		CompiledModules, err = ast.CompileModulesWithOpt(modules, opts)
		if err != nil {
			CompiledModules = nil
			return nil, err
		}
	}

	return CompiledModules, nil
}

var Indent string = "    "

type RegoPolicy struct {
	// Rego which describes policy behavior (see above)
	behavior string
	// Rego which describes policy objects
	objects string
	// Mutex to prevent concurrent access to fields
	mutex *sync.Mutex
	// Rego data object, used to store policy state
	data map[string]interface{}
	// Base64 encoded (JSON) policy
	base64policy string
	// Compiled modules
	compiledModules *ast.Compiler
}

type securityPolicyInternal struct {
	AllowAll   bool                       `json: "allow_all"`
	Containers []*securityPolicyContainer `json: "containers"`
}

func (sp SecurityPolicy) toInternal() (*securityPolicyInternal, error) {
	policy := new(securityPolicyInternal)
	var err error
	if policy.Containers, err = sp.Containers.toInternal(); err != nil {
		return nil, err
	}

	return policy, nil
}

func toOptions(values []string) Options {
	elements := make(map[string]string)
	for i, value := range values {
		elements[fmt.Sprint(i)] = value
	}
	return Options{
		Length:   len(values),
		Elements: elements,
	}
}

func (mounts *Mounts) Append(other []oci.Mount) {
	start := mounts.Length
	for i, mount := range other {
		mounts.Elements[fmt.Sprint(i+start)] = Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Type:        mount.Type,
			Options:     toOptions(mount.Options),
		}
	}

	mounts.Length += len(other)
}

type StringArray []string

func (array StringArray) MarshalRego() string {
	values := make([]string, len(array))
	for i, value := range array {
		values[i] = fmt.Sprintf("\"%s\"", value)
	}

	return fmt.Sprintf("[%s]", strings.Join(values, ","))
}

func writeCommand(builder *strings.Builder, command []string, indent string) error {
	array := (StringArray(command)).MarshalRego()
	_, err := builder.WriteString(fmt.Sprintf("%s\"command\": %s,\n", indent, array))
	return err
}

func (e EnvRuleConfig) MarshalRego() string {
	return fmt.Sprintf("{\"pattern\": \"%s\", \"strategy\": \"%s\"}", e.Rule, e.Strategy)
}

type EnvRuleArray []EnvRuleConfig

func (array EnvRuleArray) MarshalRego() string {
	values := make([]string, len(array))
	for i, env := range array {
		values[i] = env.MarshalRego()
	}

	return fmt.Sprintf("[%s]", strings.Join(values, ","))
}

func writeEnvRules(builder *strings.Builder, envRules []EnvRuleConfig, indent string) error {
	_, err := builder.WriteString(fmt.Sprintf("%s\"env_rules\": %s,\n", indent, EnvRuleArray(envRules).MarshalRego()))
	return err
}

func writeLayers(builder *strings.Builder, layers []string, indent string) error {
	array := (StringArray(layers)).MarshalRego()
	_, err := builder.WriteString(fmt.Sprintf("%s\"layers\": %s,\n", indent, array))
	return err
}

func (m mountInternal) MarshalRego() string {
	options := StringArray(m.Options).MarshalRego()
	return fmt.Sprintf("{\"destination\": \"%s\", \"options\": %s, \"source\": \"%s\", \"type\": \"%s\"}", m.Destination, options, m.Source, m.Type)
}

func writeMounts(builder *strings.Builder, mounts []mountInternal, indent string) error {
	values := make([]string, len(mounts))
	for i, mount := range mounts {
		values[i] = mount.MarshalRego()
	}

	_, err := builder.WriteString(fmt.Sprintf("%s\"mounts\": [%s],\n", indent, strings.Join(values, ",")))
	return err
}

func writeContainer(builder *strings.Builder, container *securityPolicyContainer, indent string) error {
	if _, err := builder.WriteString(fmt.Sprintf("%s{\n", indent)); err != nil {
		return err
	}

	if err := writeCommand(builder, container.Command, indent+Indent); err != nil {
		return err
	}

	if err := writeEnvRules(builder, container.EnvRules, indent+Indent); err != nil {
		return err
	}

	if err := writeLayers(builder, container.Layers, indent+Indent); err != nil {
		return err
	}

	if err := writeMounts(builder, container.Mounts, indent+Indent); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s\"allow_elevated\": %v,\n", indent+Indent, container.AllowElevated)); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s\"working_dir\": \"%s\"\n", indent+Indent, container.WorkingDir)); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s}", indent)); err != nil {
		return err
	}

	return nil
}

func addContainers(builder *strings.Builder, containers []*securityPolicyContainer) error {
	if _, err := builder.WriteString("containers := [\n"); err != nil {
		return err
	}

	for i, container := range containers {
		if err := writeContainer(builder, container, Indent); err != nil {
			return err
		}

		var end string
		if i < len(containers)-1 {
			end = ",\n"
		} else {
			end = "\n"
		}

		if _, err := builder.WriteString(end); err != nil {
			return err
		}
	}

	if _, err := builder.WriteString("]\n"); err != nil {
		return err
	}

	return nil
}

func (p securityPolicyInternal) MarshalRego() (string, error) {
	builder := new(strings.Builder)
	if _, err := builder.WriteString(fmt.Sprintf("package policy\nallow_all := %v\n", p.AllowAll)); err != nil {
		return "", err
	}

	if err := addContainers(builder, p.Containers); err != nil {
		return "", err
	}

	return builder.String(), nil
}

type RegoData map[string]interface{}

func (e EnvRuleConfig) MarshalData() RegoData {
	return RegoData{
		"pattern":  e.Rule,
		"strategy": string(e.Strategy),
	}
}

func (m mountInternal) MarshalData() RegoData {
	return RegoData{
		"options":     m.Options,
		"source":      m.Source,
		"destination": m.Destination,
		"type":        m.Type,
	}
}

func (p securityPolicyContainer) MarshalData() RegoData {
	envRules := make([]RegoData, len(p.EnvRules))
	for i, env := range p.EnvRules {
		envRules[i] = env.MarshalData()
	}

	mounts := make([]RegoData, len(p.Mounts))
	for i, mount := range p.Mounts {
		mounts[i] = mount.MarshalData()
	}

	return RegoData{
		"command":        p.Command,
		"env_rules":      envRules,
		"layers":         p.Layers,
		"mounts":         mounts,
		"working_dir":    p.WorkingDir,
		"allow_elevated": p.AllowElevated,
	}
}

func (p securityPolicyInternal) MarshalData() RegoData {
	containers := make([]RegoData, len(p.Containers))
	for i, container := range p.Containers {
		containers[i] = container.MarshalData()
	}

	return RegoData{
		"allow_all":  p.AllowAll,
		"containers": containers,
	}
}

func NewRegoPolicyFromBase64Json(base64policy string, defaultMounts []oci.Mount, privilegedMounts []oci.Mount) (*RegoPolicy, error) {
	securityPolicy := new(SecurityPolicy)
	if jsonPolicy, err := base64.StdEncoding.DecodeString(base64policy); err == nil {
		if err2 := json.Unmarshal(jsonPolicy, securityPolicy); err2 != nil {
			return nil, errors.Wrap(err2, "unable to unmarshal JSON policy")
		}
	} else {
		return nil, fmt.Errorf("failed to decode base64 security policy: %w", err)
	}

	if policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, defaultMounts, privilegedMounts); err == nil {
		policy.base64policy = base64policy
		return policy, nil
	} else {
		return nil, err
	}
}

func NewRegoPolicyFromSecurityPolicy(securityPolicy *SecurityPolicy, defaultMounts []oci.Mount, privilegedMounts []oci.Mount) (*RegoPolicy, error) {
	if policy, err := securityPolicy.toInternal(); err == nil {
		return newRegoPolicyFromInternal(policy, defaultMounts, privilegedMounts)
	} else {
		return nil, fmt.Errorf("error converting to internal format: %w", err)
	}
}

func newRegoPolicyFromInternal(securityPolicy *securityPolicyInternal, defaultMounts []oci.Mount, privilegedMounts []oci.Mount) (*RegoPolicy, error) {
	policy := new(RegoPolicy)
	policy.behavior = PolicyCode
	policy.data = map[string]interface{}{
		"started":         []string{},
		"defaultMounts":   []interface{}{},
		"sandboxPrefix":   guestpath.SandboxMountPrefix,
		"hugePagesPrefix": guestpath.HugePagesMountPrefix,
	}

	modules := map[string]string{
		"policy.rego":    PolicyCode,
		"framework.rego": FrameworkCode,
	}

	if code, err := securityPolicy.MarshalRego(); err == nil {
		modules["objects.rego"] = code
		policy.objects = code
	} else {
		return nil, err
	}

	policy.mutex = new(sync.Mutex)
	policy.base64policy = ""

	policy.ExtendDefaultMounts(defaultMounts)
	policy.ExtendDefaultMounts(privilegedMounts)

	// TODO temporary hack for debugging policies until GCS logging design
	// and implementation is finalized. This option should be changed to
	// "true" if debugging is desired.
	debug := false

	opts := ast.CompileOpts{
		EnablePrintStatements: debug,
	}

	if compiled, err := ast.CompileModulesWithOpt(modules, opts); err == nil {
		policy.compiledModules = compiled
	} else {
		return nil, fmt.Errorf("rego compilation failed: %w", err)
	}

	return policy, nil
}

func (policy RegoPolicy) Query(input map[string]interface{}) (rego.ResultSet, error) {
	store := inmem.NewFromObject(policy.data)

	var buf bytes.Buffer
	rule := input["name"].(string)
	query := rego.New(
		rego.Query(fmt.Sprintf("data.policy.%s", rule)),
		rego.Compiler(policy.compiledModules),
		rego.Input(input),
		rego.Store(store),
		rego.PrintHook(topdown.NewPrintHook(&buf)))

	ctx := context.Background()
	results, err := query.Eval(ctx)
	if err != nil {
		return results, err
	}

	output := buf.String()
	if len(output) > 0 {
		fmt.Println(output)
	}

	return results, nil
}

func (policy *RegoPolicy) EnforceDeviceMountPolicy(target string, deviceHash string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	input := map[string]interface{}{
		"name":       "mount_device",
		"target":     target,
		"deviceHash": deviceHash,
	}
	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		if devices, found := policy.data["devices"]; found {
			deviceMap := devices.(map[string]string)
			if _, e := deviceMap[target]; e {
				return fmt.Errorf("device %s already mounted", target)
			}
			deviceMap[target] = deviceHash
		} else {
			policy.data["devices"] = map[string]string{target: deviceHash}
		}
		return nil
	} else {
		return errors.New("device mount not allowed by policy")
	}
}

func (policy *RegoPolicy) EnforceOverlayMountPolicy(containerID string, layerPaths []string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	input := map[string]interface{}{
		"name":        "mount_overlay",
		"containerID": containerID,
		"layerPaths":  layerPaths,
	}
	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		// we store the mapping of container ID -> layerPaths for later
		// use in EnforceCreateContainerPolicy here.
		if containers, found := policy.data["containers"]; found {
			containerMap := containers.(map[string]interface{})
			if _, found := containerMap[containerID]; found {
				return fmt.Errorf("container %s already mounted", containerID)
			} else {
				containerMap[containerID] = map[string]interface{}{
					"containerID": containerID,
					"layerPaths":  layerPaths,
				}
			}
		} else {
			policy.data["containers"] = map[string]interface{}{
				containerID: map[string]interface{}{
					"containerID": containerID,
					"layerPaths":  layerPaths,
				},
			}
		}
		return nil
	} else {
		return errors.New("overlay mount not allowed by policy")
	}
}

func (policy *RegoPolicy) EnforceCreateContainerPolicy(containerID string,
	argList []string,
	envList []string,
	workingDir string,
	sandboxID string,
	mounts []oci.Mount,
) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	// first, we need to obtain the overlay filestytem information
	// which was stored in EnforceOverlayMountPolicy
	var containerInfo map[string]interface{}
	if containers, found := policy.data["containers"]; found {
		containerMap := containers.(map[string]interface{})
		if container, found := containerMap[containerID]; found {
			containerInfo = container.(map[string]interface{})
		} else {
			return fmt.Errorf("container %s does not have a filesystem", containerID)
		}
	} else {
		return fmt.Errorf("container %s does not have a filesystem", containerID)
	}

	input := map[string]interface{}{
		"name":         "create_container",
		"argList":      argList,
		"envList":      envList,
		"workingDir":   workingDir,
		"sandboxDir":   spec.SandboxMountsDir(sandboxID),
		"hugePagesDir": spec.HugePagesMountsDir(sandboxID),
		"mounts":       mounts,
	}

	// this adds the overlay layerPaths array to the input
	for key, value := range containerInfo {
		input[key] = value
	}

	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		started := policy.data["started"].([]string)
		policy.data["started"] = append(started, containerID)
		containerInfo["argList"] = argList
		containerInfo["envList"] = envList
		containerInfo["workingDir"] = workingDir
		return nil
	} else {
		input["name"] = "reason"
		input["rule"] = "create_container"
		result, err := policy.Query(input)
		if err != nil {
			return err
		}

		reasons := []string{}
		for _, reason := range result[0].Expressions[0].Value.([]interface{}) {
			reasons = append(reasons, reason.(string))
		}
		return fmt.Errorf("container creation not allowed by policy. Reasons: [%s]", strings.Join(reasons, ","))
	}
}

func (policy *RegoPolicy) EnforceDeviceUnmountPolicy(unmountTarget string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	devices := policy.data["devices"].(map[string]string)
	delete(devices, unmountTarget)

	return nil
}

func (policy *RegoPolicy) ExtendDefaultMounts(mounts []oci.Mount) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	defaultMounts := policy.data["defaultMounts"].([]interface{})
	for _, mount := range mounts {
		defaultMounts = append(defaultMounts, map[string]interface{}{
			"destination": mount.Destination,
			"source":      mount.Source,
			"options":     mount.Options,
			"type":        mount.Type,
		})
	}
	policy.data["defaultMounts"] = defaultMounts
	return nil
}

func (policy *RegoPolicy) EncodedSecurityPolicy() string {
	return policy.base64policy
}
