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
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;

/**
 * System as outlined in Appendix E of https://eprint.iacr.org/2019/169
 */
public class UacsIncentiveSystem implements StandaloneRepresentable {
    @Represented
    public BilinearGroup group;
    @Represented(restorer = "group::getZn")
    public Zn zp;
    @Represented(restorer = "group::getG1")
    public GroupElement w, g,h;
    @Represented
    public PSExtendedSignatureScheme psSigs;
    @Represented
    public CommitmentScheme commitmentSchemeForDamgard;
    @Represented
    public Integer rangeBase = 256;
    @Represented
    public Integer rangePower = 8;
    @Represented(restorer = "setMembershipRestorer")
    public SetMembershipPublicParameters setMembershipPp;

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

    public UacsIncentiveSystem(Representation repr) {
        new ReprUtil(this).register(r -> new SetMembershipPublicParameters(group, r), "setMembershipRestorer").deserialize(repr);
        w.precomputePow();
        g.precomputePow();
        h.precomputePow();
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

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
