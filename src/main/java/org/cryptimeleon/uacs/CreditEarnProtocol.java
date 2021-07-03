package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.craco.protocols.base.BaseProtocol;
import org.cryptimeleon.craco.protocols.base.BaseProtocolInstance;
import org.cryptimeleon.craco.protocols.base.AdHocSchnorrProof;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CreditEarnProtocol extends BaseProtocol {
    private UacsIncentiveSystem pp;
    private PSExtendedVerificationKey pk;

    public CreditEarnProtocol(UacsIncentiveSystem pp, PSExtendedVerificationKey pk) {
        super("user", "provider");
        this.pp = pp;
        this.pk = pk;
    }

    @Override
    public CreditEarnProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new CreditEarnProtocolInstance(((EarnCommonInput) commonInput).k, ((UacsIncentiveSystem.UserInput) secretInput).token);
        if (role.equals("provider"))
            return new CreditEarnProtocolInstance(((EarnCommonInput) commonInput).k, ((UacsIncentiveSystem.ProviderInput) secretInput).sk);
        throw new IllegalArgumentException("Unknown role");
    }

    public CreditEarnProtocolInstance instantiateUser(int k, Token token) {
        return instantiateProtocol("user", new EarnCommonInput(k), new UacsIncentiveSystem.UserInput(token));
    }

    public CreditEarnProtocolInstance instantiateProvider(int k, PSSigningKey sk) {
        return instantiateProtocol("provider", new EarnCommonInput(k), new UacsIncentiveSystem.ProviderInput(sk));
    }

    public static class EarnCommonInput implements CommonInput {
        public final int k;

        public EarnCommonInput(int k) {
            this.k = k;
        }
    }

    public class CreditEarnProtocolInstance extends BaseProtocolInstance {
        private Token token;
        private PSSigningKey sk;
        private int k;

        private GroupElement sigma0prime, sigma1prime;
        private GroupElement sigma0primeprime, sigma1primeprime;
        private Token resultToken;
        private Zn.ZnElement usk, dsid, dsrnd, v;
        private Zn.ZnElement rPrime;

        public CreditEarnProtocolInstance(int k, Token token) {
            super(CreditEarnProtocol.this, "user");
            this.k = k;
            this.token = token;
            this.usk = token.usk;
            this.dsid = token.dsid;
            this.dsrnd = token.dsrnd;
            this.v = token.v;
        }

        public CreditEarnProtocolInstance(int k, PSSigningKey sk) {
            super(CreditEarnProtocol.this, "provider");
            this.k = k;
            this.sk = sk;
        }

        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {
                case 0 -> { //send randomized signature and start proof
                    //Randomize signature
                    rPrime = pp.zp.getUniformlyRandomElement();
                    Zn.ZnElement r = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = token.sig.getGroup1ElementSigma1().pow(r).compute();
                    sigma1prime = token.sig.getGroup1ElementSigma2().pow(r).op(token.sig.getGroup1ElementSigma1().pow(r.mul(rPrime))).compute();
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());

                    //Prove valid signature
                    runArgumentConcurrently("sigProof", getValidSignatureProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                }
                case 2 -> { //send proof response
                    //Nothing to do
                }
                case 4 -> { //receive blinded signature and unblind
                    sigma0primeprime = pp.group.getG1().restoreElement(receive("sigma0primeprime"));
                    sigma1primeprime = pp.group.getG1().restoreElement(receive("sigma1primeprime"));
                    PSSignature sigmaStar = new PSSignature(sigma0primeprime, sigma1primeprime.op(sigma0primeprime.pow(rPrime.neg())));
                    resultToken = new Token(usk, dsid, dsrnd, v.add(pp.zp.valueOf(k)), sigmaStar);
                    if (!pp.verifyToken(resultToken, pk))
                        throw new IllegalStateException("Invalid signature");
                    terminate();
                }
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //provider
            switch (round) {
                case 1 -> { //receive randomized signature and send proof challenge
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime"));
                    runArgumentConcurrently("sigProof", getValidSignatureProof().instantiateVerifier(null));
                }
                case 3 -> { //check proof (implicit) and send updated signature
                    Zn.ZnElement rPrimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0primeprime = sigma0prime.pow(rPrimeprime).compute();
                    sigma1primeprime = sigma1prime.op(sigma0prime.pow(sk.getExponentsYi().get(3).mul(k))).pow(rPrimeprime).compute();
                    send("sigma0primeprime", sigma0primeprime.getRepresentation());
                    send("sigma1primeprime", sigma1primeprime.getRepresentation());
                    terminate();
                }
            }
        }

        public Token getUserResult() {
            return resultToken;
        }

        private InteractiveArgument getValidSignatureProof() {
            BilinearMap e = pp.group.getBilinearMap();
            if (sigma0prime.isNeutralElement())
                throw new IllegalStateException("sigma0 is the neutral group element");
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearStatement("psVerify",
                            e.applyExpr(sigma0prime, pk.getGroup2ElementTildeX().op(pk.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", "dsid", "dsrnd", "v"))))
                            .isEqualTo(e.applyExpr(sigma1prime.op(sigma0prime.inv().pow("rPrime")), pk.getGroup2ElementTildeG()))
                    ).buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}
