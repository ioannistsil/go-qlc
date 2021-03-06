/*
 * Copyright (c) 2019 QLC Chain Team
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package commands

import (
	"fmt"

	"github.com/abiosoft/ishell"
	"github.com/pkg/errors"
	"github.com/qlcchain/go-qlc/common/types"
	"github.com/qlcchain/go-qlc/rpc"
	"github.com/spf13/cobra"
)

func walletList() {
	if interactive {
		c := &ishell.Cmd{
			Name: "walletlist",
			Help: "return wallet list",
			Func: func(c *ishell.Context) {
				if HelpText(c, nil) {
					return
				}
				if err := CheckArgs(c, nil); err != nil {
					Warn(err)
					return
				}
				err := wallets()
				if err != nil {
					Warn(err)
					return
				}

			},
		}
		shell.AddCmd(c)
	} else {
		var wlCmd = &cobra.Command{
			Use:   "walletlist",
			Short: "wallet address list",
			Run: func(cmd *cobra.Command, args []string) {
				err := wallets()
				if err != nil {
					cmd.Println(err)
					return
				}
			},
		}
		rootCmd.AddCommand(wlCmd)
	}
}

func wallets() error {
	client, err := rpc.Dial(endpointP)
	if err != nil {
		return err
	}
	defer client.Close()
	var addresses []types.Address
	err = client.Call(&addresses, "wallet_list")
	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return errors.New("no account ,you can try import one!")
	} else {
		for _, v := range addresses {
			if interactive {
				Info(v)
			} else {
				fmt.Println(v)
			}
		}
	}

	return nil
}
