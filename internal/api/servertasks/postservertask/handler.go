package postservertask

import (
	"encoding/json"
	"net/http"

	"github.com/gameap/gameap/internal/api/base"
	serversbase "github.com/gameap/gameap/internal/api/servers/base"
	"github.com/gameap/gameap/internal/domain"
	"github.com/gameap/gameap/internal/repositories"
	"github.com/gameap/gameap/pkg/api"
	"github.com/gameap/gameap/pkg/auth"
	"github.com/pkg/errors"
)

type Handler struct {
	serverTasksRepo repositories.ServerTaskRepository
	serverFinder    *serversbase.ServerFinder
	abilityChecker  *serversbase.AbilityChecker
	responder       base.Responder
}

func NewHandler(
	serverTasksRepo repositories.ServerTaskRepository,
	serversRepo repositories.ServerRepository,
	rbac base.RBAC,
	responder base.Responder,
) *Handler {
	return &Handler{
		serverTasksRepo: serverTasksRepo,
		serverFinder:    serversbase.NewServerFinder(serversRepo, rbac),
		abilityChecker:  serversbase.NewAbilityChecker(rbac),
		responder:       responder,
	}
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session := auth.SessionFromContext(ctx)
	if !session.IsAuthenticated() {
		h.responder.WriteError(ctx, rw, api.WrapHTTPError(
			errors.New("user not authenticated"),
			http.StatusUnauthorized,
		))

		return
	}

	inputReader := api.NewInputReader(r)

	serverID, err := inputReader.ReadUint("server")
	if err != nil {
		h.responder.WriteError(ctx, rw, api.WrapHTTPError(
			errors.WithMessage(err, "invalid server id"),
			http.StatusBadRequest,
		))

		return
	}

	server, err := h.serverFinder.FindUserServer(ctx, session.User, serverID)
	if err != nil {
		h.responder.WriteError(ctx, rw, err)

		return
	}

	err = h.abilityChecker.CheckOrError(
		ctx,
		session.User.ID,
		server.ID,
		[]domain.AbilityName{domain.AbilityNameGameServerTasks},
	)
	if err != nil {
		h.responder.WriteError(ctx, rw, err)

		return
	}

	input := &serverTaskInput{}
	err = json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		h.responder.WriteError(ctx, rw, api.WrapHTTPError(
			errors.WithMessage(err, "invalid request body"),
			http.StatusBadRequest,
		))

		return
	}

	err = input.Validate()
	if err != nil {
		h.responder.WriteError(ctx, rw, errors.WithMessage(err, "validation failed"))

		return
	}

	serverTask, err := input.ToDomain(serverID)
	if err != nil {
		h.responder.WriteError(ctx, rw, api.WrapHTTPError(
			err,
			http.StatusBadRequest,
		))

		return
	}

	err = h.serverTasksRepo.Save(ctx, serverTask)
	if err != nil {
		h.responder.WriteError(ctx, rw, errors.WithMessage(err, "failed to save server task"))

		return
	}

	response := newServerTaskResponseFromServerTask(serverTask)

	rw.WriteHeader(http.StatusCreated)
	h.responder.Write(ctx, rw, response)
}
