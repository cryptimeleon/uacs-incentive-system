package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedSignatureScheme;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

/**
 * System as outlined in Appendix E of https://eprint.iacr.org/2019/169
 */
public class UacsIncentiveSystem {
    public final BilinearGroup group;
    public final Zn zp;
    public final GroupElement w, g,h;
    public final SetMembershipPublicParameters zkpp;
    public final PSExtendedSignatureScheme psSigs;

    public UacsIncentiveSystem(BilinearGroup group) {
        this.group = group;
        zp = group.getZn();
        w = group.getG1().getUniformlyRandomElement().precomputePow();
        g = group.getG1().getUniformlyRandomElement().precomputePow();
        h = group.getG1().getUniformlyRandomElement().precomputePow();
        zkpp = SetMembershipPublicParameters.generateInterval(group, 0, 1000);
        psSigs = new PSExtendedSignatureScheme(new PSPublicParameters(group));
    }

    public KeyPair<GroupElement, Zn.ZnElement> keyGen() {
        Zn.ZnElement sk = zp.getUniformlyRandomElement();
        GroupElement pk = w.pow(sk).precomputePow();
        return new KeyPair<>(pk, sk);
    }

    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKeyGen() {
        return psSigs.generateKeyPair(4);
    }
}
