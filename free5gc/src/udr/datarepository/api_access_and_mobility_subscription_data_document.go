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
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	"free5gc/src/udr/logger"
	"free5gc/src/udr/producer"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HTTPQueryAmData - Retrieves the access and mobility subscription data of a UE
func HTTPQueryAmData(ctx *gin.Context) {

	req := http_wrapper.NewRequest(ctx.Request, nil)
	req.Params["ueId"] = ctx.Params.ByName("ueId")
	req.Params["servingPlmnId"] = ctx.Params.ByName("servingPlmnId")

	rsp := producer.HandleQueryAmData(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.DataRepoLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		ctx.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		ctx.Data(rsp.Status, "application/json", responseBody)
	}
}
