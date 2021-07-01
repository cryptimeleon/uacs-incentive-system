package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.*;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

/**
 * System as outlined in Appendix E of https://eprint.iacr.org/2019/169
 */
public class UacsIncentiveSystem {
    public final BilinearGroup group;
    public final Zn zp;
    public final GroupElement w, g,h;
    public final SetMembershipPublicParameters zkpp;
    public final PSExtendedSignatureScheme psSigs;
    public final CommitmentScheme commitmentSchemeForDamgard;

    public UacsIncentiveSystem(BilinearGroup group) {
        this.group = group;
        zp = group.getZn();
        w = group.getG1().getUniformlyRandomElement().precomputePow();
        g = group.getG1().getUniformlyRandomElement().precomputePow();
        h = group.getG1().getUniformlyRandomElement().precomputePow();
        zkpp = SetMembershipPublicParameters.generateInterval(group, 0, 1000);
        psSigs = new PSExtendedSignatureScheme(new PSPublicParameters(group));
        commitmentSchemeForDamgard = new HashThenCommitCommitmentScheme(new PedersenCommitmentScheme(group.getG1(), 1), new SHA256HashFunction());
    }

    public KeyPair<GroupElement, Zn.ZnElement> keyGen() {
        Zn.ZnElement sk = zp.getUniformlyRandomElement();
        GroupElement pk = w.pow(sk).precomputePow();
        return new KeyPair<>(pk, sk);
    }

    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKeyGen() {
        return psSigs.generateKeyPair(4);
    }

    public boolean verifyToken(Token token, PSVerificationKey issuerPk) {
        Vector<RingElementPlainText> signedMessage = token.getMessageVector().map(RingElementPlainText::new);
        return psSigs.verify(issuerPk, token.sig, signedMessage);
    }

    public static class ProviderInput implements SecretInput {
        public final PSSigningKey sk;

        public ProviderInput(PSSigningKey sk) {
            this.sk = sk;
        }
    }

    public static class UserInput implements SecretInput {
        public final Zn.ZnElement usk;
        public final Token token;

        public UserInput(Token token) {
            this.token = token;
            this.usk = token.usk;
        }

        public UserInput(Zn.ZnElement usk) {
            this.usk = usk;
            this.token = null;
        }
    }
}
