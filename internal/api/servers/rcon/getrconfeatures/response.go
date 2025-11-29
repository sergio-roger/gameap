package getrconfeatures

import (
	"github.com/gameap/gameap/pkg/quercon/rcon"
)

type featuresResponse struct {
	Rcon          bool `json:"rcon"`
	PlayersManage bool `json:"playersManage"`
}

func newFeaturesResponse(gameCode string, engine string) featuresResponse {
	return featuresResponse{
		Rcon:          rcon.IsProtocolSupported(rcon.Protocol(engine)),
		PlayersManage: rcon.IsPlayerManagementSupported(gameCode),
	}
}
