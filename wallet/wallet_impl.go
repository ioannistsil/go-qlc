/*
 * Copyright (c) 2018 QLC Chain Team
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package wallet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/qlcchain/go-qlc/common"
	"github.com/qlcchain/go-qlc/common/types"
	"github.com/qlcchain/go-qlc/crypto/ed25519"
	"github.com/qlcchain/go-qlc/ledger"
	"github.com/qlcchain/go-qlc/ledger/db"
	"github.com/qlcchain/go-qlc/log"
	"go.uber.org/zap"
	"io"
)

const (
	idPrefixId byte = iota
	idPrefixIds
	idPrefixVersion
	idPrefixSeed
	idPrefixIndex
	idPrefixRepresentation
	idPrefixWork
)

const (
	Version            = 1
	searchAccountCount = 100
)

type WalletStore struct {
	io.Closer
	db.Store
	ledger ledger.Ledger
	log    *zap.SugaredLogger
}

type Session struct {
	db.Store
	ledger          ledger.Ledger
	log             *zap.SugaredLogger
	maxAccountCount uint64
	walletId        []byte
	password        []byte // TODO: password fan
}

var (
	EmptyIdErr = errors.New("empty wallet id")
)

func (ws *WalletStore) NewSession(walletId []byte) *Session {
	s := &Session{
		Store:           ws.Store,
		ledger:          ws.ledger,
		log:             log.NewLogger("wallet session" + hex.EncodeToString(walletId)),
		maxAccountCount: searchAccountCount,
		walletId:        walletId,
		password:        []byte{},
	}
	//update database
	err := s.UpdateInTx(func(txn db.StoreTxn) error {
		var migrations []db.Migration
		return txn.Upgrade(migrations)
	})
	if err != nil {
		ws.log.Fatal(err)
	}
	return s
}

func (s *Session) Init() error {
	err := s.SetDeterministicIndex(1)
	if err != nil {
		return err
	}
	_ = s.SetVersion(Version)
	//default password is empty
	_ = s.EnterPassword("")

	seed, err := types.NewSeed()
	if err != nil {
		return err
	}
	err = s.SetSeed(seed[:])

	return err
}

//Remove wallet by id
func (s *Session) Remove() error {
	return s.UpdateInTx(func(txn db.StoreTxn) error {
		for _, val := range []byte{idPrefixId, idPrefixVersion, idPrefixSeed, idPrefixRepresentation} {
			seedKey := []byte{val}
			seedKey = append(seedKey, s.walletId...)
			err := txn.Delete(seedKey)
			if err != nil {
				s.log.Fatal(err)
			}
		}

		return nil
	})
}

func (s *Session) EnterPassword(password string) error {
	s.setPassword(password)
	_, err := s.GetSeed()
	return err
}

func (s *Session) GetWalletId() ([]byte, error) {
	if len(s.walletId) == 0 {
		return nil, EmptyIdErr
	}
	return s.walletId, nil
}

func (s *Session) GetRepresentative() (types.Address, error) {
	var address types.Address
	err := s.ViewInTx(func(txn db.StoreTxn) error {

		key := s.getKey(idPrefixRepresentation)
		return txn.Get(key, func(val []byte, b byte) error {
			addr, err := types.BytesToAddress(val)
			address = addr
			return err
		})
	})

	return address, err
}

func (s *Session) SetRepresentative(address types.Address) error {
	return s.UpdateInTx(func(txn db.StoreTxn) error {
		key := s.getKey(idPrefixRepresentation)
		return txn.Set(key, address[:])
	})
}

func (s *Session) GetSeed() ([]byte, error) {
	var seed []byte
	err := s.ViewInTx(func(txn db.StoreTxn) error {

		key := s.getKey(idPrefixSeed)
		return txn.Get(key, func(val []byte, b byte) error {
			s, err := DecryptSeed(val, s.getPassword())
			seed = append(seed, s...)
			return err
		})
	})

	return seed, err
}

func (s *Session) SetSeed(seed []byte) error {
	encryptSeed, err := EncryptSeed(seed, s.getPassword())

	if err != nil {
		return err
	}

	return s.UpdateInTx(func(txn db.StoreTxn) error {
		key := s.getKey(idPrefixSeed)
		return txn.Set(key, encryptSeed)
	})
}

func (s *Session) ResetDeterministicIndex() error {
	return s.SetDeterministicIndex(0)
}

func (s *Session) GetBalances() (map[types.Hash]types.Balance, error) {
	cache := map[types.Hash]types.Balance{}

	session := s.ledger.NewLedgerSession(false)
	defer session.Close()

	accounts, err := s.GetAccounts()

	if err != nil {
		return cache, err
	}

	for _, account := range accounts {
		if am, err := session.GetAccountMeta(account); err == nil {
			for _, tm := range am.Tokens {
				if balance, ok := cache[tm.Type]; ok {
					b := cache[tm.Type]
					cache[tm.Type] = balance.Add(b)
				} else {
					cache[tm.Type] = balance
				}
			}
		}
	}

	return cache, nil
}

func (s *Session) SearchPending() error {
	session := s.ledger.NewLedgerSession(false)
	defer session.Close()

	accounts, err := s.GetAccounts()

	if err != nil {
		return err
	}
	for _, account := range accounts {
		if keys, err := session.Pending(account); err == nil {
			for _, key := range keys {
				if block, err := session.GetBlock(key.Hash); err == nil {
					//TODO: implement
					s.log.Debug(block)
					//_, _ = s.Receive(block)
				}
			}
		}
	}

	return nil
}

func (s *Session) Send(source types.Address, token types.Hash, to types.Address, amount types.Balance) (*types.Block, error) {
	_, priv, err := s.GetRawKey(source)
	if err != nil {
		return nil, err
	}

	session := s.ledger.NewLedgerSession(false)
	defer session.Close()
	tm, err := session.GetTokenMeta(source, token)
	if err != nil {
		return nil, err
	}
	balance, err := session.TokenBalance(source, token)
	if err != nil {
		return nil, err
	}
	repBlock, err := session.GetBlock(tm.RepBlock)
	if err != nil {
		return nil, err
	}
	if balance.Compare(amount) == types.BalanceCompBigger {
		newBalance := balance.Sub(amount)
		sendBlock, _ := types.NewBlock(types.State)

		if sb, ok := sendBlock.(*types.StateBlock); ok {
			sb.Address = source
			sb.Token = token
			sb.Link = to.ToHash()
			sb.Balance = newBalance
			sb.Previous = tm.Header
			sb.Representative = repBlock.(*types.StateBlock).Representative
			sb.Work, _ = s.GetWork(source)
			h := sb.GetHash()
			sb.Signature, err = h.Sign(priv)
			if err != nil {
				return nil, err
			}
			if !sb.IsValid() {
				sb.Work = s.generateWork(sb.Root())
			}
		}
		return &sendBlock, nil
	} else {
		return nil, fmt.Errorf("not enought balance(%s) of %s", balance.BigInt(), amount.BigInt())
	}
}

func (s *Session) Receive(sendBlock types.Block) (*types.Block, error) {
	hash := sendBlock.GetHash()
	if _, ok := sendBlock.(*types.StateBlock); !ok {
		return nil, fmt.Errorf("invalid state sendBlock(%s)", hash.String())
	}

	session := s.ledger.NewLedgerSession(false)
	defer session.Close()

	// block not exist
	if exist, err := session.HasBlock(hash); !exist || err != nil {
		return nil, fmt.Errorf("sendBlock(%s) does not exist", hash.String())
	}

	tm, err := session.Token(hash)
	if err != nil {
		return nil, err
	}
	account := tm.BelongTo
	info, err := session.GetPending(types.PendingKey{Address: account, Hash: hash})
	if err != nil {
		return nil, err
	}

	repBlock, err := session.GetBlock(tm.RepBlock)
	if err != nil {
		return nil, fmt.Errorf("can not fetch account(%s) rep", account)
	}

	_, priv, err := s.GetRawKey(account)

	if err != nil {
		return nil, err
	}
	receiveBlock, _ := types.NewBlock(types.State)

	if sb, ok := receiveBlock.(*types.StateBlock); ok {
		sb.Address = account
		sb.Balance = info.Amount
		sb.Previous = tm.Header
		sb.Link = hash
		sb.Representative = repBlock.(*types.StateBlock).Representative
		sb.Token = tm.Type
		sb.Extra = types.Hash{}
		sb.Work, err = s.GetWork(account)
		h := sb.GetHash()
		sb.Signature, err = h.Sign(priv)
		if err != nil {
			return nil, err
		}
		if !sb.IsValid() {
			sb.Work = s.generateWork(sb.Root())
		}
	}

	return &receiveBlock, nil
}

func (s *Session) Change(account types.Address, representative types.Address) (*types.Block, error) {
	if exist := s.IsAccountExist(account); !exist {
		return nil, fmt.Errorf("account[%s] is not exist", account.String())
	}

	session := s.ledger.NewLedgerSession(false)
	defer session.Close()
	if _, err := session.GetAccountMeta(representative); err != nil {
		return nil, fmt.Errorf("invalid representative[%s]", representative.String())
	}

	//get latest chain token block
	hash := session.Latest(account, common.ChainTokenType)

	if hash.IsZero() {
		return nil, fmt.Errorf("account [%s] does not have the main chain account", account.String())
	}

	block, err := session.GetBlock(hash)
	if err != nil {
		return nil, err
	}
	if sb, ok := block.(*types.StateBlock); ok {
		changeBlock, err := types.NewBlock(types.State)
		if err != nil {
			return nil, err
		}
		tm, err := session.GetTokenMeta(account, common.ChainTokenType)
		if newSb, ok := changeBlock.(*types.StateBlock); ok {
			_, priv, err := s.GetRawKey(account)
			if err != nil {
				return nil, err
			}
			newSb.Address = account
			newSb.Balance = tm.Balance
			newSb.Previous = tm.Header
			newSb.Link = account.ToHash()
			newSb.Representative = representative
			newSb.Token = sb.Token
			newSb.Extra = types.Hash{}
			newSb.Work, err = s.GetWork(account)
			if err != nil {
				return nil, err
			}
			hash := newSb.GetHash()
			newSb.Signature, err = hash.Sign(priv)
			if err != nil {
				return nil, err
			}

			if !newSb.IsValid() {
				newSb.Work = s.generateWork(newSb.Root())
				_ = s.setWork(account, newSb.Work)
			}
		}
		return &changeBlock, nil
	}

	return nil, fmt.Errorf("invalid state block (%s) of account[%s]", hash, account.String())
}

func (s *Session) Import(content string, password string) error {
	panic("implement me")
}

func (s *Session) Export(path string) error {
	panic("implement me")
}

func (s *Session) GetVersion() (int64, error) {
	var i int64
	err := s.ViewInTx(func(txn db.StoreTxn) error {

		key := s.getKey(idPrefixVersion)
		return txn.Get(key, func(val []byte, b byte) error {
			i, _ = binary.Varint(val)
			return nil
		})
	})

	return i, err
}

func (s *Session) SetVersion(version int64) error {
	return s.UpdateInTx(func(txn db.StoreTxn) error {
		key := s.getKey(idPrefixVersion)
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutVarint(buf, version)
		return txn.Set(key, buf[:n])
	})
}

func (s *Session) GetDeterministicIndex() (int64, error) {
	var i int64
	err := s.ViewInTx(func(txn db.StoreTxn) error {

		key := s.getKey(idPrefixIndex)
		return txn.Get(key, func(val []byte, b byte) error {
			i, _ = binary.Varint(val)
			return nil
		})
	})

	return i, err
}

func (s *Session) SetDeterministicIndex(index int64) error {
	return s.UpdateInTx(func(txn db.StoreTxn) error {
		key := s.getKey(idPrefixIndex)
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutVarint(buf, index)
		return txn.Set(key, buf[:n])
	})
}

func (s *Session) GetWork(account types.Address) (types.Work, error) {
	var work types.Work
	err := s.ViewInTx(func(txn db.StoreTxn) error {
		key := []byte{idPrefixWork}
		key = append(key, account[:]...)
		return txn.Get(key, func(val []byte, b byte) error {
			return work.UnmarshalBinary(val)
		})
	})

	if err != nil {
		return work, err
	}

	return work, nil
}

func (s *Session) generateWork(hash types.Hash) types.Work {
	var work types.Work
	worker, _ := types.NewWorker(work, hash)
	return worker.NewWork()
	//
	////cache to db
	//_ = s.setWork(hash, work)
}

func (s *Session) setWork(account types.Address, work types.Work) error {
	return s.UpdateInTx(func(txn db.StoreTxn) error {
		key := []byte{idPrefixWork}
		key = append(key, account[:]...)
		buf := make([]byte, work.Len())
		err := work.MarshalBinaryTo(buf)
		if err != nil {
			return err
		}
		return txn.Set(key, buf)
	})
}

func (s *Session) IsAccountExist(addr types.Address) bool {
	_, _, err := s.GetRawKey(addr)
	return err == nil
}

func (s *Session) ValidPassword() bool {
	_, err := s.GetSeed()
	return err == nil
}

func (s *Session) ChangePassword(password string) error {
	seed, err := s.GetSeed()
	if err != nil {
		return nil
	}
	//set new password
	s.setPassword(password)
	return s.SetSeed(seed)
}

func (s *Session) GetRawKey(account types.Address) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	session := s.ledger.NewLedgerSession(false)
	defer session.Close()

	_, err := session.GetAccountMeta(account)
	if err != nil {
		return nil, nil, err
	}

	index, err := s.GetDeterministicIndex()
	if err != nil {
		index = 0
	}

	seedArray, err := s.GetSeed()
	if err != nil {
		return nil, nil, err
	}

	max := max(uint32(index), uint32(s.maxAccountCount))
	seed := hex.EncodeToString(seedArray)

	for i := uint32(0); i < max; i++ {
		pub, priv, err := types.KeypairFromSeed(seed, uint32(i))
		if err != nil {
			s.log.Fatal(err)
		}
		address := types.PubToAddress(pub)
		if address == account {
			return pub, priv, nil
		}
	}

	return nil, nil, fmt.Errorf("can not fetch account[%s]'s raw key", account.String())
}

func (s *Session) GetAccounts() (accounts []types.Address, err error) {
	session := s.ledger.NewLedgerSession(false)
	defer session.Close()

	index, err := s.GetDeterministicIndex()
	if err != nil {
		index = 0
	}

	if seedArray, err := s.GetSeed(); err == nil {
		max := max(uint32(index), uint32(s.maxAccountCount))
		seed := hex.EncodeToString(seedArray)

		for i := uint32(0); i < max; i++ {
			if pub, _, err := types.KeypairFromSeed(seed, uint32(i)); err == nil {
				address := types.PubToAddress(pub)
				if _, err := session.GetAccountMeta(address); err == nil {
					accounts = append(accounts, address)
				}
			}
		}
	}

	return
}

func (s *Session) getKey(t byte) []byte {
	var key []byte
	key = append(key, t)
	key = append(key, s.walletId...)
	return key[:]
}

func (s *Session) getPassword() []byte {
	return s.password
}

//TODO: implement password fan
func (s *Session) setPassword(password string) {
	s.password = []byte(password)
}

// max returns the larger of x or y.
func max(x, y uint32) uint32 {
	if x < y {
		return y
	}
	return x
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}