package prototype;

import org.cryptimeleon.craco.protocols.base.BaseProtocol;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.uacs.*;

public class Test {
    @org.junit.Test
    public void systemRun() {
        UacsIncentiveSystem incentiveSystem = new UacsIncentiveSystem(new BarretoNaehrigBilinearGroup(80));

        //Keygen
        SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey = incentiveSystem.issuerKeyGen();
        KeyPair<GroupElement, Zn.ZnElement> userKey = incentiveSystem.keyGen();

        //IssueJoin
        IssueJoinProtocol protocol = new IssueJoinProtocol(incentiveSystem, issuerKey.getVerificationKey());
        IssueJoinProtocol.IssueJoinProtocolInstance userInstance = protocol.instantiateUser(userKey.pk, userKey.sk);
        IssueJoinProtocol.IssueJoinProtocolInstance providerInstance = protocol.instantiateProvider(userKey.pk, issuerKey.getSigningKey());
        protocol.runProtocolLocally(userInstance, providerInstance);
        Token token = userInstance.getUserResult();

        //CreditEarn
        CreditEarnProtocol earnProtocol = new CreditEarnProtocol(incentiveSystem, issuerKey.getVerificationKey());
        CreditEarnProtocol.CreditEarnProtocolInstance earnUserInstance = earnProtocol.instantiateUser(5, token);
        CreditEarnProtocol.CreditEarnProtocolInstance earnProviderInstance = earnProtocol.instantiateProvider(5, issuerKey.getSigningKey());
        earnProtocol.runProtocolLocally(earnUserInstance, earnProviderInstance);
        Token updatedToken = earnUserInstance.getUserResult();

        //Spend
        SpendDeductProtocol spendProtocol = new SpendDeductProtocol(incentiveSystem, issuerKey.getVerificationKey());
        SpendDeductProtocol.SpendDeductProtocolInstance spendUserInstance = spendProtocol.instantiateUser(3, updatedToken);
        SpendDeductProtocol.SpendDeductProtocolInstance spendProviderInstance = spendProtocol.instantiateProvider(3, updatedToken.dsid, issuerKey.getSigningKey());
        spendProtocol.runProtocolLocally(spendUserInstance, spendProviderInstance);
        Token lastToken = spendUserInstance.getUserResult();
        DoubleSpendTag dstag = spendProviderInstance.getProviderResult();
    }
}
