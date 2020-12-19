package ome

const (
	MetaServiceCertificate = "service-certificate"
	MetaTokenVerifyingKey  = "token-verify-key"

	MetaApiAccessKey    = "api-access-credentials"
	MetaApiAccessSecret = "api-access-secret"
)

const (
	UnknownServiceType        = 0
	CAServiceType             = 1
	AuthenticationServiceType = 2
	OrganizationServiceType   = 3
	TokenStoreServiceType     = 4
	DataServiceType           = 5
	FileStorageServiceType    = 6
	AppRegistryServiceType    = 7
	UserAccountsServiceType   = 8
	FilesServerServiceType    = 9
)
