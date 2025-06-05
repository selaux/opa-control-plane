package global.systemtypes["entitlements:1.0"].library.sample.car_info_store

role_bindings := {
	"car-creators": {"subjects": {"ids": ["sales", "store-managers", "senior-leadership-team"]}},
	"status-updaters": {"subjects": {"ids": ["sales", "store-managers", "senior-leadership-team"]}},
	"status-deleters": {"subjects": {"ids": ["store-managers", "senior-leadership-team"]}},
	"car-updaters": {"subjects": {"ids": ["store-managers", "senior-leadership-team"]}},
	"car-readers": {"subjects": {"membership-attributes": {"is_employee": true}}},
	"status-readers": {"subjects": {"membership-attributes": {"is_employee": true}}},
}
