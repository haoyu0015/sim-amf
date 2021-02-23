package util

import (
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	"free5gc/src/pcf/context"
	"free5gc/src/pcf/factory"
	"free5gc/src/pcf/logger"
	"os"

	"github.com/google/uuid"
)

// Init PCF Context from config flie
func InitpcfContext(context *context.PCFContext) {
	config := factory.PcfConfig
	logger.UtilLog.Infof("pcfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.PcfName != "" {
		context.Name = configuration.PcfName
	}
	sbi := configuration.Sbi
	context.NrfUri = configuration.NrfUri
	context.UriScheme = models.UriScheme(sbi.Scheme)
	context.HttpIPv4Address = "127.0.0.1" // default localhost
	context.HttpIpv4Port = 29507          // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.HttpIPv4Address = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.HttpIpv4Port = sbi.Port
		}
		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}
		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.UtilLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.UtilLog.Info("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}
	serviceList := configuration.ServiceList
	context.InitNFService(serviceList, config.Info.Version)
	context.TimeFormat = configuration.TimeFormat
	context.DefaultBdtRefId = configuration.DefaultBdtRefId
	for _, service := range context.NfService {
		context.PcfServiceUris[service.ServiceName] = service.ApiPrefix + "/" + string(service.ServiceName) + "/" + (*service.Versions)[0].ApiVersionInUri
		context.PcfSuppFeats[service.ServiceName], _ = openapi.NewSupportedFeature(service.SupportedFeatures)
	}
}
