package pkg

type trustedEntitiesStore struct {
	Issuers map[string]bool
}

func (t *trustedEntitiesStore) isTrusted(did string) bool {
	if v, ok := t.Issuers[did]; ok {
		return v
	}
	return false
}

var TrustedEntities = trustedEntitiesStore{
	Issuers: make(map[string]bool),
}
