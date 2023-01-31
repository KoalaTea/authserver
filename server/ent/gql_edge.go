// Code generated by ent, DO NOT EDIT.

package ent

import "context"

func (oac *OIDCAuthCode) AccessRequest(ctx context.Context) (*AccessRequest, error) {
	result, err := oac.Edges.AccessRequestOrErr()
	if IsNotLoaded(err) {
		result, err = oac.QueryAccessRequest().Only(ctx)
	}
	return result, MaskNotFound(err)
}

func (oac *OIDCAuthCode) Session(ctx context.Context) (*OIDCSession, error) {
	result, err := oac.Edges.SessionOrErr()
	if IsNotLoaded(err) {
		result, err = oac.QuerySession().Only(ctx)
	}
	return result, MaskNotFound(err)
}
