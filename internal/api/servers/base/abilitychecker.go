package base

import (
	"context"
	"net/http"

	"github.com/gameap/gameap/internal/api/base"
	"github.com/gameap/gameap/internal/domain"
	"github.com/gameap/gameap/pkg/api"
	"github.com/pkg/errors"
)

// AbilityChecker is responsible for checking server abilities.
type AbilityChecker struct {
	rbac base.RBAC
}

func NewAbilityChecker(rbac base.RBAC) *AbilityChecker {
	return &AbilityChecker{
		rbac: rbac,
	}
}

// Check checks if a user has all the specified abilities for a server.
// It returns true if the user is an admin or has all the specific abilities for the server.
func (c *AbilityChecker) Check(
	ctx context.Context,
	userID uint,
	serverID uint,
	abilities []domain.AbilityName,
) (bool, error) {
	isAdmin, err := c.rbac.Can(ctx, userID, []domain.AbilityName{domain.AbilityNameAdminRolesPermissions})
	if err != nil {
		return false, errors.WithMessage(err, "failed to check admin permissions")
	}

	if isAdmin {
		return true, nil
	}

	hasAbility, err := c.rbac.CanForEntity(
		ctx,
		userID,
		domain.EntityTypeServer,
		serverID,
		abilities,
	)
	if err != nil {
		return false, errors.WithMessage(err, "failed to check ability")
	}

	return hasAbility, nil
}

// CheckOrError checks if a user has all the specified abilities for a server.
// It returns an error if the user doesn't have all the abilities.
func (c *AbilityChecker) CheckOrError(
	ctx context.Context,
	userID uint,
	serverID uint,
	abilities []domain.AbilityName,
) error {
	hasAbility, err := c.Check(ctx, userID, serverID, abilities)
	if err != nil {
		return err
	}

	if !hasAbility {
		return api.WrapHTTPError(
			errors.Errorf("user does not have required permissions"),
			http.StatusForbidden,
		)
	}

	return nil
}
