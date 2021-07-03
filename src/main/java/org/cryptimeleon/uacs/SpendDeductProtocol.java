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
import org.cryptimeleon.math.expressions.exponent.BasicNamedExponentVariableExpr;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class SpendDeductProtocol extends BaseProtocol {
    private UacsIncentiveSystem pp;
    private PSExtendedVerificationKey pk;

    public SpendDeductProtocol(UacsIncentiveSystem pp, PSExtendedVerificationKey pk) {
        super("user", "provider");
        this.pp = pp;
        this.pk = pk;
    }

    @Override
    public SpendDeductProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new SpendDeductProtocolInstance(((SpendCommonInput) commonInput).k, ((UacsIncentiveSystem.UserInput) secretInput).token);
        if (role.equals("provider"))
            return new SpendDeductProtocolInstance(((SpendCommonInput) commonInput).k, ((SpendCommonInput) commonInput).dsid, ((UacsIncentiveSystem.ProviderInput) secretInput).sk);
        throw new IllegalArgumentException("Unknown role");
    }

    public SpendDeductProtocolInstance instantiateUser(int k, Token token) {
        return instantiateProtocol("user", new SpendCommonInput(k, token.dsid), new UacsIncentiveSystem.UserInput(token));
    }

    public SpendDeductProtocolInstance instantiateProvider(int k, Zn.ZnElement dsid, PSSigningKey sk) {
        return instantiateProtocol("provider", new SpendCommonInput(k, dsid), new UacsIncentiveSystem.ProviderInput(sk));
    }

    public static class SpendCommonInput implements CommonInput {
        public final int k;
        public final Zn.ZnElement dsid;

        public SpendCommonInput(int k, Zn.ZnElement dsid) {
            this.k = k;
            this.dsid = dsid;
        }
    }

    public class SpendDeductProtocolInstance extends BaseProtocolInstance {
        private Token token;
        private PSSigningKey sk;
        private int k;
        private Zn.ZnElement dsid;

        private Zn.ZnElement r, rPrime, rPrimePrime, rCommitmentC;
        private Zn.ZnElement gamma;
        private Zn.ZnElement dsidStarUsr, dsidStarProvider, openStar;
        private GroupElement CstarUser0, CstarUser1;
        private GroupElement Cdsidstar0, Cdsidstar1;
        private GroupElement sigma0prime, sigma1prime;
        private GroupElement sigma0primeprime, sigma1primeprime;
        private GroupElement commitmentC;
        private Zn.ZnElement schnorrTrickC;
        private GroupElement ctrace0, ctrace1;
        private Token resultToken;
        private DoubleSpendTag dstag;
        private Zn.ZnElement usk, dsrnd, v;
        private Zn.ZnElement dsidStar, dsrndStar;


        public SpendDeductProtocolInstance(int k, Token token) {
            super(SpendDeductProtocol.this, "user");
            this.k = k;
            this.token = token;
            this.usk = token.usk;
            this.dsid = token.dsid;
            this.dsrnd = token.dsrnd;
            this.v = token.v;
        }

        public SpendDeductProtocolInstance(int k, Zn.ZnElement dsid, PSSigningKey sk) {
            super(SpendDeductProtocol.this, "provider");
            this.k = k;
            this.dsid = dsid;
            this.sk = sk;
        }

        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {
                case 0 -> { //choose dsidStarUser and commit to it
                    dsidStarUsr = pp.zp.getUniformlyRandomElement();
                    openStar = pp.zp.getUniformlyRandomElement();
                    CstarUser0 = pp.g.pow(dsidStarUsr).op(pp.h.pow(openStar)).compute();
                    CstarUser1 = pp.g.pow(openStar).compute();
                    send("CstarUser0", CstarUser0.getRepresentation());
                    send("CstarUser1", CstarUser1.getRepresentation());
                }
                case 2 -> { //Prepare updated credential values and run proof
                    gamma = pp.zp.restoreElement(receive("gamma"));
                    dsidStarProvider = pp.zp.restoreElement(receive("dsidStarProvider"));

                    Cdsidstar0 = CstarUser0.op(pp.g.pow(dsidStarProvider)).compute();
                    Cdsidstar1 = CstarUser1;

                    //Prepare pre-signature for new token
                    dsidStar = dsidStarUsr.add(dsidStarProvider);
                    dsrndStar = pp.zp.getUniformlyRandomElement();
                    rCommitmentC = pp.zp.getUniformlyRandomElement();
                    commitmentC = pk.getGroup1ElementsYi().innerProduct(Vector.of(usk, dsidStar, dsrndStar, v.sub(pp.zp.valueOf(k)))).op(pk.getGroup1ElementG().pow(rCommitmentC)).compute();

                    //Put usk into Schnorr trick
                    schnorrTrickC = usk.mul(gamma).add(dsrnd);

                    //Encrypt dsid*
                    GroupElement dsidStarGroupElem = pp.w.pow(dsidStar);
                    r = pp.zp.getUniformlyRandomNonzeroElement();
                    ctrace0 = pp.w.pow(r).compute();
                    ctrace1 = pp.w.pow(r.mul(usk)).op(dsidStarGroupElem).compute();

                    //Randomize credential
                    rPrime = pp.zp.getUniformlyRandomElement();
                    rPrimePrime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = token.sig.getGroup1ElementSigma1().pow(rPrimePrime).compute();
                    sigma1prime = token.sig.getGroup1ElementSigma2().op(token.sig.getGroup1ElementSigma1().pow(rPrime)).pow(rPrimePrime).compute();

                    //Send values
                    send("C", commitmentC.getRepresentation());
                    send("c", schnorrTrickC.getRepresentation());
                    send("ctrace0", ctrace0.getRepresentation());
                    send("ctrace1", ctrace1.getRepresentation());
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());

                    //Run proof
                    runArgumentConcurrently("spendProof", getSpendProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    //getSpendProof().debugProof(null, AdHocSchnorrProof.witnessOf(this));
                }
                case 4 -> { //Proof response
                    //Nothing to do.
                }
                case 6 -> { //receive blinded signature and unblind
                    sigma0primeprime = pp.group.getG1().restoreElement(receive("sigma0primeprime"));
                    sigma1primeprime = pp.group.getG1().restoreElement(receive("sigma1primeprime"));
                    PSSignature sigmaStar = new PSSignature(sigma0primeprime, sigma1primeprime.op(sigma0primeprime.pow(rCommitmentC.neg())).compute());
                    resultToken = new Token(usk, dsidStar, dsrndStar, v.sub(pp.zp.valueOf(k)), sigmaStar);
                    if (!pp.verifyToken(resultToken, pk))
                        throw new IllegalStateException("Invalid signature");
                    terminate();
                }
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //provider
            switch (round) {
                case 1 -> { //receive commitment to user share of dsidStar, reply with gamma and provider's share.
                    CstarUser0 = pp.group.getG1().restoreElement(receive("CstarUser0"));
                    CstarUser1 = pp.group.getG1().restoreElement(receive("CstarUser1"));
                    gamma = pp.zp.getUniformlyRandomElement();
                    send("gamma", gamma.getRepresentation());
                    dsidStarProvider = pp.zp.getUniformlyRandomElement();
                    send("dsidStarProvider", dsidStarProvider.getRepresentation());
                    Cdsidstar0 = CstarUser0.op(pp.g.pow(dsidStarProvider)).compute();
                    Cdsidstar1 = CstarUser1;
                }
                case 3 -> { //Receive stuff and send proof challenge
                    commitmentC = pp.group.getG1().restoreElement(receive("C"));
                    schnorrTrickC = pp.zp.restoreElement(receive("c"));
                    ctrace0 = pp.group.getG1().restoreElement(receive("ctrace0"));
                    ctrace1 = pp.group.getG1().restoreElement(receive("ctrace1"));
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime"));

                    runArgumentConcurrently("spendProof", getSpendProof().instantiateVerifier(null));
                }
                case 5 -> { //check proof (implicit) and send updated signature. Output dstag.
                    Zn.ZnElement rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0primeprime = pk.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1primeprime = commitmentC.op(pk.getGroup1ElementG().pow(sk.getExponentX())).pow(rPrimeprimeprime).compute();
                    dstag = new DoubleSpendTag(schnorrTrickC, gamma, ctrace0, ctrace1);
                    send("sigma0primeprime", sigma0primeprime.getRepresentation());
                    send("sigma1primeprime", sigma1primeprime.getRepresentation());
                    terminate();
                }
            }
        }

        public Token getUserResult() {
            return resultToken;
        }

        public DoubleSpendTag getProviderResult() {
            return dstag;
        }

        private InteractiveArgument getSpendProof() {
            BilinearMap e = pp.group.getBilinearMap();
            if (sigma0prime.isNeutralElement())
                throw new IllegalStateException("sigma0 is the neutral group element");
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearExponentStatement("uskSchnorrTrick", schnorrTrickC.isEqualTo(gamma.asExponentExpression().mul("usk").add("dsrnd")))
                    .addLinearStatement("psVerify",
                            e.applyExpr(sigma0prime, pk.getGroup2ElementTildeX().op(pk.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", "dsid", "dsrnd", "v"))))
                            .isEqualTo(e.applyExpr(sigma1prime.op(sigma0prime.inv().pow("rPrime")), pk.getGroup2ElementTildeG())))
                    .addSmallerThanPowerStatement("enoughPoints", new BasicNamedExponentVariableExpr("v").sub(k), pp.rangeBase, pp.rangePower, pp.setMembershipPp)
                    .addLinearStatement("ctrace0open", ctrace0.isEqualTo(pp.w.pow("r")))
                    .addLinearStatement("ctrace1open", ctrace1.isEqualTo(ctrace0.pow("usk").op(pp.w.pow("dsidStar"))))
                    .addLinearStatement("updatedMessageOpen", commitmentC.isEqualTo(pk.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "dsidStar", "dsrndStar", pp.zp.valueOf(k).neg().asExponentExpression().add("v"))).op(pk.getGroup1ElementG().pow("rCommitmentC"))))
                    .addLinearStatement("encryptionOfDsidStar0", Cdsidstar0.isEqualTo(pp.g.pow("dsidStar").op(pp.h.pow("openStar"))))
                    .addLinearStatement("encryptionOfDsidStar1", Cdsidstar1.isEqualTo(pp.g.pow("openStar")))
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}
