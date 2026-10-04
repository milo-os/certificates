// SPDX-License-Identifier: AGPL-3.0-only

package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

const (
	crdDir = "../../config/base/crd/bases"
	iamDir = "../../config/components/iam"
)

var resourceVerbs = sets.New("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection")

var subresourceVerbs = []string{"get", "update", "patch"}

type crd struct {
	Spec struct {
		Group string `json:"group"`
		Names struct {
			Plural string `json:"plural"`
		} `json:"names"`
		Versions []struct {
			Served       bool           `json:"served"`
			Subresources map[string]any `json:"subresources"`
		} `json:"versions"`
	} `json:"spec"`
}

type protectedResource struct {
	Spec struct {
		ServiceRef struct {
			Name string `json:"name"`
		} `json:"serviceRef"`
		Plural       string   `json:"plural"`
		Permissions  []string `json:"permissions"`
		Subresources []struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		} `json:"subresources"`
	} `json:"spec"`
}

type role struct {
	Spec struct {
		IncludedPermissions []string `json:"includedPermissions"`
	} `json:"spec"`
}

func readYAML(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no files match %s", pattern)
	}
	return files
}

func servedSubresources(t *testing.T) map[string]sets.Set[string] {
	t.Helper()
	served := map[string]sets.Set[string]{}
	for _, f := range glob(t, filepath.Join(crdDir, "*.yaml")) {
		var c crd
		readYAML(t, f, &c)
		if c.Spec.Group != GroupVersion.Group {
			continue
		}
		subs := sets.New[string]()
		for _, v := range c.Spec.Versions {
			if !v.Served {
				continue
			}
			for name := range v.Subresources {
				subs.Insert(name)
			}
		}
		served[c.Spec.Names.Plural] = subs
	}
	if len(served) == 0 {
		t.Fatalf("no %s CRDs under %s", GroupVersion.Group, crdDir)
	}
	return served
}

func protectedResources(t *testing.T) map[string]protectedResource {
	t.Helper()
	prs := map[string]protectedResource{}
	for _, f := range glob(t, filepath.Join(iamDir, "protected-resources", "*.yaml")) {
		var pr protectedResource
		readYAML(t, f, &pr)
		if pr.Spec.ServiceRef.Name != GroupVersion.Group {
			continue
		}
		prs[pr.Spec.Plural] = pr
	}
	if len(prs) == 0 {
		t.Fatalf("no %s ProtectedResources under %s", GroupVersion.Group, iamDir)
	}
	return prs
}

func declaredPermissions(t *testing.T) sets.Set[string] {
	t.Helper()
	declared := sets.New[string]()
	for plural, pr := range protectedResources(t) {
		base := GroupVersion.Group + "/" + plural
		for _, verb := range pr.Spec.Permissions {
			declared.Insert(base + "." + verb)
		}
		for _, sub := range pr.Spec.Subresources {
			for _, verb := range sub.Permissions {
				declared.Insert(base + "/" + sub.Name + "." + verb)
			}
		}
	}
	return declared
}

func TestServedSubresourcesAreDeclared(t *testing.T) {
	prs := protectedResources(t)
	declared := declaredPermissions(t)
	for plural, subs := range servedSubresources(t) {
		if _, ok := prs[plural]; !ok {
			t.Errorf("%s has no ProtectedResource", plural)
			continue
		}
		for _, sub := range sets.List(subs) {
			for _, verb := range subresourceVerbs {
				permission := GroupVersion.Group + "/" + plural + "/" + sub + "." + verb
				if !declared.Has(permission) {
					t.Errorf("%s is served but %s is not declared", plural+"/"+sub, permission)
				}
			}
		}
	}
}

func TestResourcePermissionsAreRequestVerbs(t *testing.T) {
	for plural, pr := range protectedResources(t) {
		for _, verb := range pr.Spec.Permissions {
			if !resourceVerbs.Has(verb) {
				t.Errorf("%s declares %q, which no request asks for", plural, verb)
			}
		}
	}
}

func TestRolesGrantOnlyDeclaredPermissions(t *testing.T) {
	declared := declaredPermissions(t)
	for _, f := range glob(t, filepath.Join(iamDir, "roles", "*.yaml")) {
		if filepath.Base(f) == "kustomization.yaml" {
			continue
		}
		var r role
		readYAML(t, f, &r)
		for _, permission := range r.Spec.IncludedPermissions {
			if strings.HasPrefix(permission, GroupVersion.Group+"/") && !declared.Has(permission) {
				t.Errorf("%s grants %s, which no ProtectedResource declares", filepath.Base(f), permission)
			}
		}
	}
}
