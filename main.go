package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit_addr struct {
	// default uses variable name and secret visibility.
	Pk       twistededwards.Point `gnark:",public"`
	R_point  twistededwards.Point `gnark:",public"`
	Addr     twistededwards.Point
	R_scalar frontend.Variable
}

type Circuit_env struct {
	Pk       twistededwards.Point `gnark:",public"`
	X        twistededwards.Point `gnark:",public"`
	Cm       twistededwards.Point `gnark:",public"`
	H        twistededwards.Point `gnark:",public"`
	V_scalar frontend.Variable
	R_scalar frontend.Variable
}

func (circuit *Circuit_addr) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC("seed", api)
	if err != nil {
		return err
	}
	params, err := twistededwards.NewEdCurve(api.Curve())

	var addr, addr_r, R twistededwards.Point
	addr_r.ScalarMulFixedBase(api, circuit.Addr.X, circuit.Addr.Y, circuit.R_scalar, params)
	mimc.Write(addr_r.X, addr_r.Y)
	result := mimc.Sum()
	addr.ScalarMulFixedBase(api, circuit.Addr.X, circuit.Addr.Y, result, params)
	api.AssertIsEqual(addr.X, circuit.Pk.X)
	api.AssertIsEqual(addr.Y, circuit.Pk.Y)

	R.ScalarMulFixedBase(api, params.BaseX, params.BaseY, circuit.R_scalar, params)
	api.AssertIsEqual(circuit.R_point.X, R.X)
	api.AssertIsEqual(circuit.R_point.Y, R.Y)

	return nil
}

func (circuit *Circuit_env) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC("seed", api)
	if err != nil {
		return err
	}
	params, err := twistededwards.NewEdCurve(api.Curve())
	var X, Cm, preimage, hv, lhs twistededwards.Point

	X.ScalarMulFixedBase(api, circuit.Pk.X, circuit.Pk.Y, circuit.R_scalar, params)
	api.AssertIsEqual(X.X, circuit.X.X)
	api.AssertIsEqual(X.Y, circuit.X.Y)

	preimage.ScalarMulFixedBase(api, params.BaseX, params.BaseY, circuit.R_scalar, params)
	mimc.Write(preimage.X, preimage.Y)
	result := mimc.Sum()
	lhs.ScalarMulFixedBase(api, params.BaseX, params.BaseY, result, params)
	hv.ScalarMulNonFixedBase(api, &circuit.H, circuit.V_scalar, params)
	Cm.AddGeneric(api, &lhs, &hv, params)
	api.AssertIsEqual(Cm.X, circuit.Cm.X)
	api.AssertIsEqual(Cm.Y, circuit.Cm.Y)
	return nil
}

func main() {
	println("test")
	frontend.RegisterDefaultBuilder(backend.GROTH16, r1cs.NewBuilder)

	{
		var circuit Circuit_addr
		ccs, err2 := frontend.Compile(ecc.BLS12_381, backend.GROTH16, &circuit)
		if err2 != nil {
			panic(err2)
		}
		cs := ccs.GetNbConstraints()
		i, s, p := ccs.GetNbVariables()
		println("circuit_addr constraints is :", cs)
		println("circuit_addr internal is :", i, " secret is :", s, " public is :", p)
	}

	{
		var circuit Circuit_env
		ccs, err2 := frontend.Compile(ecc.BLS12_381, backend.GROTH16, &circuit)
		if err2 != nil {
			panic(err2)
		}
		cs := ccs.GetNbConstraints()
		i, s, p := ccs.GetNbVariables()
		println("circuit_env constraints is :", cs)
		println("circuit_env internal is :", i, " secret is :", s, " public is :", p)
	}

}
