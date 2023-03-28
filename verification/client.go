package verification

import (
	"fmt"
)

type Support struct {
	Simulation    bool
	ExtendTci     bool
	AutoInit      bool
	Tagging       bool
	RotateContext bool
}

// An interface to define how to test and send messages to a DPE instance.
type Transport interface {
	// Send a command to the DPE instance.
	SendCmd(buf []byte) ([]byte, error)
}

type Client struct {
	transport   Transport
	Profile     uint32
	Version     uint32
	MaxTciNodes uint32
	Flags       uint32
}

// NewClient initializes a new DPE client, including querying the underlying implementation for its profile.
func NewClient(t Transport) (*Client, error) {
	client := Client{transport: t}
	rsp, err := client.GetProfile()
	if err != nil {
		return nil, fmt.Errorf("could not query DPE profile: %w", err)
	}
	client.Profile = rsp.Profile
	client.Version = rsp.Version
	client.MaxTciNodes = rsp.MaxTciNodes
	client.Flags = rsp.Flags
	return &client, nil
}

func (c *Client) InitializeContext(cmd *InitCtxCmd) (*InitCtxResp, error) {
	var respStruct InitCtxResp

	if _, err := execCommand(c.transport, CommandInitializeContext, c.Profile, cmd, &respStruct); err != nil {
		return nil, err
	}

	return &respStruct, nil
}

func (c *Client) GetProfile() (*GetProfileResp, error) {
	// GetProfile does not take any parameters.
	cmd := struct{}{}

	// Define an anonymous struct for the actual wire-format members of GetProfile,
	// since GetProfileResp includes the actual profile copied from the response header.
	respStruct := struct {
		Version     uint32
		MaxTciNodes uint32
		Flags       uint32
	}{}

	respHdr, err := execCommand(c.transport, CommandGetProfile, c.Profile, cmd, &respStruct)
	if err != nil {
		return nil, err
	}

	return &GetProfileResp{
		// Special case for GetProfile: copy the profile from the inner packet header into the response structure.
		Profile:     respHdr.Profile,
		Version:     respStruct.Version,
		MaxTciNodes: respStruct.MaxTciNodes,
		Flags:       respStruct.Flags,
	}, nil
}

// Send the command to destroy a context.
func (c *Client) DestroyContext(cmd *DestroyCtxCmd) error {
	// DestroyContext does not return any parameters.
	respStruct := struct{}{}

	if _, err := execCommand(c.transport, CommandInitializeContext, c.Profile, cmd, &respStruct); err != nil {
		return err
	}

	return nil
}

func (s *Support) ToFlags() uint32 {
	flags := uint32(0)
	if s.Simulation {
		flags |= (1 << 31)
	}
	if s.ExtendTci {
		flags |= (1 << 30)
	}
	if s.AutoInit {
		flags |= (1 << 29)
	}
	if s.Tagging {
		flags |= (1 << 28)
	}
	if s.RotateContext {
		flags |= (1 << 27)
	}
	return flags
}
