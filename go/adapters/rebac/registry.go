package rebac

import (
	"context"
	"fmt"

	"hop.top/pact-go/adapter"
)

// Registry is the mapping registry of profile RB-6: it maps the
// authenticated principal to the Check subject and the resource of the actual
// operation to the Check object, in one realm. An entry belongs to exactly one
// realm (RB-4), so a lookup in another realm finds nothing.
type Registry interface {
	// Subject returns the subject id of principal in realm; the Check user is
	// user:<subject id>. ok is false when the realm holds no entry for the
	// principal. An error means the registry cannot answer.
	Subject(ctx context.Context, realm adapter.Realm, principal string) (id string, ok bool, err error)
	// Object returns the object id of resource in realm; the Check object is
	// <object type>:<object id>, the type taken from the relation table. ok
	// is false when the realm holds no entry for the resource.
	Object(ctx context.Context, realm adapter.Realm, resource string) (id string, ok bool, err error)
}

// SubjectEntry maps a principal of a realm to a subject id.
type SubjectEntry struct {
	Realm     adapter.Realm
	Principal string
	SubjectID string
}

// ObjectEntry maps a resource of a realm to an object id.
type ObjectEntry struct {
	Realm    adapter.Realm
	Resource string
	ObjectID string
}

// StaticRegistry is a [Registry] over fixed entries, the explicit and
// versioned mapping of draft 17.2 as configuration. Build it with
// [NewStaticRegistry].
type StaticRegistry struct {
	subjects map[adapter.Realm]map[string]string
	objects  map[adapter.Realm]map[string]string
}

// NewStaticRegistry validates the entries and returns the registry. Each id
// has the form of RB-6; a principal or a resource has at most one entry per
// realm, and no two principals of a realm share a subject id, since the
// mapping is one to one per store.
func NewStaticRegistry(subjects []SubjectEntry, objects []ObjectEntry) (*StaticRegistry, error) {
	r := &StaticRegistry{subjects: map[adapter.Realm]map[string]string{}, objects: map[adapter.Realm]map[string]string{}}
	used := map[adapter.Realm]map[string]bool{}
	for _, e := range subjects {
		if e.Principal == "" || !validID(e.SubjectID) || len(subjectType)+1+len(e.SubjectID) > maxUser {
			return nil, fmt.Errorf("rebac: subject entry %q: the subject id is not of the form of RB-6", e.Principal)
		}
		if r.subjects[e.Realm] == nil {
			r.subjects[e.Realm], used[e.Realm] = map[string]string{}, map[string]bool{}
		}
		if _, dup := r.subjects[e.Realm][e.Principal]; dup || used[e.Realm][e.SubjectID] {
			return nil, fmt.Errorf("rebac: subject entry %q: a principal or a subject id twice in one realm", e.Principal)
		}
		r.subjects[e.Realm][e.Principal] = e.SubjectID
		used[e.Realm][e.SubjectID] = true
	}
	for _, e := range objects {
		if e.Resource == "" || !validID(e.ObjectID) {
			return nil, fmt.Errorf("rebac: object entry %q: the object id is not of the form of RB-6", e.Resource)
		}
		if r.objects[e.Realm] == nil {
			r.objects[e.Realm] = map[string]string{}
		}
		if _, dup := r.objects[e.Realm][e.Resource]; dup {
			return nil, fmt.Errorf("rebac: object entry %q twice in one realm", e.Resource)
		}
		r.objects[e.Realm][e.Resource] = e.ObjectID
	}
	return r, nil
}

// Subject implements [Registry].
func (r *StaticRegistry) Subject(_ context.Context, realm adapter.Realm, principal string) (string, bool, error) {
	id, ok := r.subjects[realm][principal]
	return id, ok, nil
}

// Object implements [Registry].
func (r *StaticRegistry) Object(_ context.Context, realm adapter.Realm, resource string) (string, bool, error) {
	id, ok := r.objects[realm][resource]
	return id, ok, nil
}
