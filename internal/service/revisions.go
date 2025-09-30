package service

import "sync"

var revisions *Revisions = &Revisions{
	m: map[string]string{},
}

type Revisions struct {
	mut sync.Mutex
	m   map[string]string
}

func (r *Revisions) GetLatest(bundle string) *string {
	r.mut.Lock()
	defer r.mut.Unlock()

	revision, ok := r.m[bundle]
	if !ok {
		return nil
	}
	return &revision
}

func (r *Revisions) SetLatest(bundle, revision string) {
	r.mut.Lock()
	defer r.mut.Unlock()

	r.m[bundle] = revision
}
