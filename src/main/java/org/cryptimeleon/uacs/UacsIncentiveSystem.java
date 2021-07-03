package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.*;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;

/**
 * System as outlined in Appendix E of https://eprint.iacr.org/2019/169
 */
public class UacsIncentiveSystem {
    public final BilinearGroup group;
    public final Zn zp;
    public final GroupElement w, g,h;
    public final PSExtendedSignatureScheme psSigs;
    public final CommitmentScheme commitmentSchemeForDamgard;
    public final int rangeBase = 256;
    public final int rangePower = 8;
    public final SetMembershipPublicParameters setMembershipPp;

    public UacsIncentiveSystem(BilinearGroup group) {
        this.group = group;
        zp = group.getZn();
        w = group.getG1().getUniformlyRandomElement().precomputePow();
        g = group.getG1().getUniformlyRandomElement().precomputePow();
        h = group.getG1().getUniformlyRandomElement().precomputePow();
        psSigs = new PSExtendedSignatureScheme(new PSPublicParameters(group));
        commitmentSchemeForDamgard = DamgardTechnique.generateCommitmentScheme(group.getG1());
        setMembershipPp = SetMembershipPublicParameters.generateInterval(group, 0, rangeBase);
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

    public Token restoreToken(Representation repr) {
        return new Token(zp, psSigs, repr);
    }

    public DoubleSpendTag restoreDoubleSpendTag(Representation repr) {
        return new DoubleSpendTag(group.getG1(), repr);
    }
}
