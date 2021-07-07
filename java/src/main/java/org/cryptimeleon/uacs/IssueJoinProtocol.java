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
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class IssueJoinProtocol extends BaseProtocol {
    private UacsIncentiveSystem pp;
    private PSExtendedVerificationKey pk;

    public IssueJoinProtocol(UacsIncentiveSystem pp, PSExtendedVerificationKey pk) {
        super("user", "provider");
        this.pp = pp;
        this.pk = pk;
    }

    @Override
    public IssueJoinProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new IssueJoinProtocolInstance(((IssueCommonInput) commonInput).upk, ((UacsIncentiveSystem.UserInput) secretInput).usk);
        if (role.equals("provider"))
            return new IssueJoinProtocolInstance(((IssueCommonInput) commonInput).upk, ((UacsIncentiveSystem.ProviderInput) secretInput).sk);
        throw new IllegalArgumentException("Unknown role");
    }

    public IssueJoinProtocolInstance instantiateUser(GroupElement upk, Zn.ZnElement usk) {
        return instantiateProtocol("user", new IssueCommonInput(upk), new UacsIncentiveSystem.UserInput(usk));
    }

    public IssueJoinProtocolInstance instantiateProvider(GroupElement upk, PSSigningKey sk) {
        return instantiateProtocol("provider", new IssueCommonInput(upk), new UacsIncentiveSystem.ProviderInput(sk));
    }

    public static class IssueCommonInput implements CommonInput {
        public final GroupElement upk;

        public IssueCommonInput(GroupElement upk) {
            this.upk = upk;
        }
    }

    public class IssueJoinProtocolInstance extends BaseProtocolInstance {
        private GroupElement upk;
        private Zn.ZnElement usk;
        private PSSigningKey sk;

        private Zn.ZnElement dsidUsr, dsidPrvdr, dsid;
        private Zn.ZnElement open;
        private Zn.ZnElement dsrnd, r;
        private GroupElement commitUser0, commitUser1;
        private GroupElement dsidPublic;
        private GroupElement commitDsid0, commitDsid1;
        private GroupElement c;
        private GroupElement sigma0prime, sigma1prime;
        private Token token;

        public IssueJoinProtocolInstance(GroupElement upk, Zn.ZnElement usk) {
            super(IssueJoinProtocol.this, "user");
            this.upk = upk;
            this.usk = usk;
        }

        public IssueJoinProtocolInstance(GroupElement upk, PSSigningKey sk) {
            super(IssueJoinProtocol.this, "provider");
            this.upk = upk;
            this.sk = sk;
        }

        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {
                case 0: //commit to user share of dsid
                    dsidUsr = pp.zp.getUniformlyRandomElement();
                    open = pp.zp.getUniformlyRandomElement();
                    commitUser0 = pp.g.pow(dsidUsr).op(pp.h.pow(open)).compute();
                    commitUser1 = pp.g.pow(open).compute();
                    send("Cusr0", commitUser0.getRepresentation());
                    send("Cusr1", commitUser1.getRepresentation());
                    break;
                case 2: //prove well-formedness (announcement)
                    dsidPrvdr = pp.zp.restoreElement(receive("dsidPrvdr"));
                    commitDsid0 = commitUser0.op(pp.g.pow(dsidPrvdr)).compute();
                    commitDsid1 = commitUser1;
                    dsid = dsidUsr.add(dsidPrvdr);
                    dsrnd = pp.zp.getUniformlyRandomElement();
                    r = pp.zp.getUniformlyRandomElement();
                    dsidPublic = pp.w.pow(dsid);
                    c = pk.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, dsid, dsrnd, pp.zp.getZeroElement())).op(pk.getGroup1ElementG().pow(r));
                    send("c", c.getRepresentation());
                    runArgumentConcurrently("wellFormednessProof", getWellFormednessProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    break;
                case 4: //prove well-formedness (response)
                    break;
                case 6: //receive blinded signature and unblind
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime")).op(sigma0prime.pow(r.neg()));
                    token = new Token(usk, dsid, dsrnd, pp.zp.getZeroElement(), new PSSignature(sigma0prime, sigma1prime));
                    if (!pp.verifyToken(token, pk))
                        throw new IllegalStateException("Invalid token");
                    terminate();
                    break;
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //provider
            switch (round) {
                case 1: //send provider share of dsid
                    commitUser0 = pp.group.getG1().restoreElement(receive("Cusr0"));
                    commitUser1 = pp.group.getG1().restoreElement(receive("Cusr1"));
                    dsidPrvdr = pp.zp.getUniformlyRandomElement();
                    send("dsidPrvdr", dsidPrvdr.getRepresentation());
                    commitDsid0 = commitUser0.op(pp.g.pow(dsidPrvdr)).compute();
                    commitDsid1 = commitUser1;
                    break;
                case 3: //check well-formedness (send challenge)
                    c = pp.group.getG1().restoreElement(receive("c"));
                    runArgumentConcurrently("wellFormednessProof", getWellFormednessProof().instantiateVerifier(null));
                    break;
                case 5: //check well-formedness (got last message). Send signature if valid.
                    //Check happens implicitly
                    //Signature:
                    Zn.ZnElement r = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = pk.getGroup1ElementG().pow(r).compute();
                    sigma1prime = pk.getGroup1ElementG().pow(sk.getExponentX()).op(c).pow(r).compute(); //TODO optimize: precompute X
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());
                    terminate();
                    break;
            }
        }

        public Token getUserResult() {
            return token;
        }

        private InteractiveArgument getWellFormednessProof() {
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearStatement("psCommitOpen", c.isEqualTo(pk.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "dsid", "dsrnd", pp.zp.getZeroElement())).op(pk.getGroup1ElementG().pow("r"))))
                    .addLinearStatement("upkWellFormed",  upk.isEqualTo(pp.w.pow("usk")))
                    .addLinearStatement("commitDsid0Open",  commitDsid0.isEqualTo(pp.g.pow("dsid").op(pp.h.pow("open"))))
                    .addLinearStatement("commitDsid1Open",  commitDsid1.isEqualTo(pp.g.pow("open")))
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}
