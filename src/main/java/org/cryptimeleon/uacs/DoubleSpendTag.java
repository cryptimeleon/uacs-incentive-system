package org.cryptimeleon.uacs;

import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class DoubleSpendTag {
    public final Zn.ZnElement c, gamma;
    public final GroupElement ctrace0, ctrace1;

    public DoubleSpendTag(Zn.ZnElement c, Zn.ZnElement gamma, GroupElement ctrace0, GroupElement ctrace1) {
        this.c = c;
        this.gamma = gamma;
        this.ctrace0 = ctrace0;
        this.ctrace1 = ctrace1;
    }
}
