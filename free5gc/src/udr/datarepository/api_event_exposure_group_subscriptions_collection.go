/*
 * Nudr_DataRepository API OpenAPI file
 *
 * Unified Data Repository Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package datarepository

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	"free5gc/src/udr/handler/message"
	"free5gc/src/udr/logger"

	"github.com/gin-gonic/gin"
)

// CreateEeGroupSubscriptions - Create individual EE subscription for a group of UEs or any UE
func CreateEeGroupSubscriptions(c *gin.Context) {
	var eeSubscription models.EeSubscription
	if err := c.ShouldBindJSON(&eeSubscription); err != nil {
		logger.DataRepoLog.Panic(err.Error())
	}

	req := http_wrapper.NewRequest(c.Request, eeSubscription)
	req.Params["ueGroupId"] = c.Params.ByName("ueGroupId")

	handlerMsg := message.NewHandlerMessage(message.EventCreateEeGroupSubscriptions, req)
	message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse
	for key, val := range HTTPResponse.Header {
		c.Header(key, val[0])
	}

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}

// QueryEeGroupSubscriptions - Retrieves the ee subscriptions of a group of UEs or any UE
func QueryEeGroupSubscriptions(c *gin.Context) {
	req := http_wrapper.NewRequest(c.Request, nil)
	req.Params["ueGroupId"] = c.Params.ByName("ueGroupId")

	handlerMsg := message.NewHandlerMessage(message.EventQueryEeGroupSubscriptions, req)
	message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
