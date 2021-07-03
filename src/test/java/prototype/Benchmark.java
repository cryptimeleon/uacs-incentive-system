package prototype;

import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.uacs.*;

public class Benchmark {
    UacsIncentiveSystem incentiveSystem;
    KeyPair<GroupElement, Zn.ZnElement> userKey;
    SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey;

    Token token;

    long userTime, providerTime;
    long currentPhaseStart;

    public void setup() {
        incentiveSystem = new UacsIncentiveSystem(new MclBilinearGroup());
        issuerKey = incentiveSystem.issuerKeyGen();
        userKey = incentiveSystem.keyGen();
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void join() {
        //Set up user
        startStopwatch();
        IssueJoinProtocol protocol = new IssueJoinProtocol(incentiveSystem, issuerKey.getVerificationKey());
        IssueJoinProtocol.IssueJoinProtocolInstance userInstance = protocol.instantiateUser(userKey.pk, userKey.sk);
        addTimeToUser();

        //Set up provider
        startStopwatch();
        IssueJoinProtocol protocol2 = new IssueJoinProtocol(incentiveSystem, issuerKey.getVerificationKey());
        IssueJoinProtocol.IssueJoinProtocolInstance providerInstance = protocol2.instantiateProvider(userKey.pk, issuerKey.getSigningKey());
        addTimeToProvider();

        //Run protocol
        runProtocol(userInstance, providerInstance);

        startStopwatch();
        token = userInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();
    }

    public void earn(int k) {
        //Set up user
        startStopwatch();
        CreditEarnProtocol earnProtocol = new CreditEarnProtocol(incentiveSystem, issuerKey.getVerificationKey());
        CreditEarnProtocol.CreditEarnProtocolInstance earnUserInstance = earnProtocol.instantiateUser(k, token);
        addTimeToUser();

        //Set up provider
        startStopwatch();
        CreditEarnProtocol earnProtocol2 = new CreditEarnProtocol(incentiveSystem, issuerKey.getVerificationKey());
        CreditEarnProtocol.CreditEarnProtocolInstance earnProviderInstance = earnProtocol2.instantiateProvider(k, issuerKey.getSigningKey());
        addTimeToProvider();

        runProtocol(earnUserInstance, earnProviderInstance);

        startStopwatch();
        token = earnUserInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();
    }

    public void spend(int k) {
        //Set up user
        startStopwatch();
        SpendDeductProtocol spendProtocol = new SpendDeductProtocol(incentiveSystem, issuerKey.getVerificationKey());
        SpendDeductProtocol.SpendDeductProtocolInstance spendUserInstance = spendProtocol.instantiateUser(k, token);
        addTimeToUser();

        startStopwatch();
        SpendDeductProtocol spendProtocol2 = new SpendDeductProtocol(incentiveSystem, issuerKey.getVerificationKey());
        SpendDeductProtocol.SpendDeductProtocolInstance spendProviderInstance = spendProtocol2.instantiateProvider(k, token.dsid, issuerKey.getSigningKey());
        addTimeToProvider();

        runProtocol(spendUserInstance, spendProviderInstance);

        startStopwatch();
        token = spendUserInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();

        startStopwatch();
        DoubleSpendTag dstag = spendProviderInstance.getProviderResult();
        dstag.getRepresentation();
        addTimeToProvider();
    }

    public void runProtocol(TwoPartyProtocolInstance userInstance, TwoPartyProtocolInstance providerInstance) {
        boolean isUsersTurn = userInstance.sendsFirstMessage();
        TwoPartyProtocolInstance currentParty = isUsersTurn ? userInstance : providerInstance;
        Representation message = null;

        do {
            startStopwatch();
            message = currentParty.nextMessage(message);
            addTimeTo(isUsersTurn);

            isUsersTurn = !isUsersTurn;
            currentParty = isUsersTurn ? userInstance : providerInstance;
        } while (!userInstance.hasTerminated() || !providerInstance.hasTerminated());
    }

    public void startStopwatch() {
        currentPhaseStart = System.nanoTime();
    }

    public void addTimeTo(boolean toUser) {
        if (toUser)
            addTimeToUser();
        else
            addTimeToProvider();
    }

    public void addTimeToUser() {
        userTime += System.nanoTime() - currentPhaseStart;
    }

    public void addTimeToProvider() {
        providerTime += System.nanoTime() - currentPhaseStart;
    }

    public void resetTimes() {
        userTime = 0;
        providerTime = 0;
    }

    public void printTimes(int numberIterations) {
        System.out.println("User: "+userTime/numberIterations/1000000 + " ms");
        System.out.println("Provider: "+providerTime/numberIterations/1000000 + " ms");
    }

    public static void main(String[] args) {
        try {
            Benchmark benchmark = new Benchmark();
            benchmark.setup();
            int iterations = 100;

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.join();
            System.out.println("Join");
            benchmark.printTimes(iterations);

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.earn(100);
            System.out.println("Earn");
            benchmark.printTimes(iterations);

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.spend(20);
            System.out.println("Spend");
            benchmark.printTimes(iterations);
        } catch (RuntimeException e) {
            e.printStackTrace();
        }
    }
}
