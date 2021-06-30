package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.craco.protocols.base.BaseProtocol;
import org.cryptimeleon.craco.protocols.base.BaseProtocolInstance;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.craco.sig.ps.PSVerificationKey;
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
        return new IssueJoinProtocolInstance(role, ((IssueCommonInput) commonInput).upk, );
    }

    public IssueJoinProtocolInstance instantiateUser(GroupElement upk, Zn.ZnElement usk) {
        return instantiateProtocol("user", new IssueCommonInput(upk), new IssueUserInput(usk));
    }

    public IssueJoinProtocolInstance instantiateProvider(GroupElement upk, PSSigningKey sk) {
        return instantiateProtocol("provider", new IssueCommonInput(upk), new IssueProviderInput(sk));
    }

    public static class IssueCommonInput implements CommonInput {
        public final GroupElement upk;

        public IssueCommonInput(GroupElement upk) {
            this.upk = upk;
        }
    }

    public static class IssueUserInput implements SecretInput {
        public final Zn.ZnElement usk;

        public IssueUserInput(Zn.ZnElement usk) {
            this.usk = usk;
        }
    }

    public static class IssueProviderInput implements SecretInput {
        public final PSSigningKey sk;

        public IssueProviderInput(PSSigningKey sk) {
            this.sk = sk;
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
                    runSubprotocolConcurrently("wellFormednessProof", new WellFormednessProof().getProverInstance(null, null));
                    break;
                case 4: //prove well-formedness (response)
                    break;
                case 6: //receive blinded signature
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime"));

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
                    runSubprotocolConcurrently("wellFormednessProof", new WellFormednessProof().getVerifierInstance(null));
                    break;

            }
        }

        public class WellFormednessProof extends DelegateProtocol {
            @Override
            protected SendThenDelegateFragment.ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput, SendThenDelegateFragment.ProverSpecBuilder builder) {
                builder.putWitnessValue("usk", usk);
                builder.putWitnessValue("dsid", dsid);
                builder.putWitnessValue("dsrnd", dsrnd);
                builder.putWitnessValue("r", r);
                builder.putWitnessValue("open", open);
                return builder.build();
            }

            @Override
            protected SendThenDelegateFragment.SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SendThenDelegateFragment.SubprotocolSpecBuilder builder) {
                SchnorrZnVariable usk = builder.addZnVariable("usk", pp.zp);
                SchnorrZnVariable dsid = builder.addZnVariable("dsid", pp.zp);
                SchnorrZnVariable dsrnd = builder.addZnVariable("dsrnd", pp.zp);
                SchnorrZnVariable r = builder.addZnVariable("r", pp.zp);
                SchnorrZnVariable open = builder.addZnVariable("open", pp.zp);

                builder.addSubprotocol("psCommitOpen", new LinearStatementFragment(
                        c.isEqualTo(pk.getGroup1ElementsYi().expr().innerProduct(Vector.of(usk, dsid, dsrnd, pp.zp.getZeroElement())).op(pk.getGroup1ElementG().pow(r)))
                ));
                builder.addSubprotocol("upkWellFormed", new LinearStatementFragment(
                        upk.isEqualTo(pp.w.pow(usk))
                ));
                builder.addSubprotocol("commitDsid0Open", new LinearStatementFragment(
                        commitDsid0.isEqualTo(pp.g.pow(dsid).op(pp.h.pow(open)))
                ));
                builder.addSubprotocol("commitDsid1Open", new LinearStatementFragment(
                        commitDsid1.isEqualTo(pp.g.pow(open))
                ));
                return builder.build();
            }

            @Override
            public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
                return new ZnChallengeSpace(pp.zp);
            }
        }
    }
}
