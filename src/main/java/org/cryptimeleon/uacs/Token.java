package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.RingElement;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class Token implements SecretInput {
    public final Zn.ZnElement usk, dsid, dsrnd, v;
    public final PSSignature sig;

    public Token(Zn.ZnElement usk, Zn.ZnElement dsid, Zn.ZnElement dsrnd, Zn.ZnElement v, PSSignature sig) {
        this.usk = usk;
        this.dsid = dsid;
        this.dsrnd = dsrnd;
        this.v = v;
        this.sig = sig;
    }

    public RingElementVector getMessageVector() {
        return new RingElementVector(usk, dsid, dsrnd, v);
    }
}
