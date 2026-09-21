	switch {
	case decoded.Result == nil:
		// Règle indéfinie : OPA est sain — default-deny §1, pas d'alarme.
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPAUndefined}, start)
	case decoded.Result.Allow == nil:
		err := errors.New("pep: réponse OPA sans allow (contrat rompu)")
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPABadResponse, Err: err}, start)
	case !*decoded.Result.Allow:
		// Deny métier : OPA est sain, la politique refuse — pas d'alarme.
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPADeny}, start)
	default:
		return c.finish(ctx, in, OPADecision{Allow: true, Reason: ReasonOK}, start)
	}
}
