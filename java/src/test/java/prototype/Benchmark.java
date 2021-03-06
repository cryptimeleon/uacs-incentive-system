package prototype;

import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.craco.sig.ps.PSVerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.uacs.*;
import org.junit.Test;

public class Benchmark {
    UacsIncentiveSystem incentiveSystem;
    KeyPair<GroupElement, Zn.ZnElement> userKey;
    SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey;

    Token token;

    long userTime, providerTime;
    long currentPhaseStart;

    public void setup(BilinearGroup bilinearGroup) {
        incentiveSystem = new UacsIncentiveSystem(bilinearGroup);
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
        countTowards(true);
        startStopwatch();
        IssueJoinProtocol protocol = new IssueJoinProtocol(incentiveSystem, issuerKey.getVerificationKey());
        IssueJoinProtocol.IssueJoinProtocolInstance userInstance = protocol.instantiateUser(userKey.pk, userKey.sk);
        addTimeToUser();

        //Set up provider
        countTowards(false);
        startStopwatch();
        IssueJoinProtocol protocol2 = new IssueJoinProtocol(incentiveSystem, issuerKey.getVerificationKey());
        IssueJoinProtocol.IssueJoinProtocolInstance providerInstance = protocol2.instantiateProvider(userKey.pk, issuerKey.getSigningKey());
        addTimeToProvider();

        //Run protocol
        runProtocol(userInstance, providerInstance);

        startStopwatch();
        countTowards(true);
        token = userInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();
    }

    public void earn(int k) {
        //Set up user
        countTowards(true);
        startStopwatch();
        CreditEarnProtocol earnProtocol = new CreditEarnProtocol(incentiveSystem, issuerKey.getVerificationKey());
        CreditEarnProtocol.CreditEarnProtocolInstance earnUserInstance = earnProtocol.instantiateUser(k, token);
        addTimeToUser();

        //Set up provider
        countTowards(false);
        startStopwatch();
        CreditEarnProtocol earnProtocol2 = new CreditEarnProtocol(incentiveSystem, issuerKey.getVerificationKey());
        CreditEarnProtocol.CreditEarnProtocolInstance earnProviderInstance = earnProtocol2.instantiateProvider(k, issuerKey.getSigningKey());
        addTimeToProvider();

        runProtocol(earnUserInstance, earnProviderInstance);

        countTowards(true);
        startStopwatch();
        token = earnUserInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();
    }

    public void spend(int k) {
        //Set up user
        countTowards(true);
        startStopwatch();
        SpendDeductProtocol spendProtocol = new SpendDeductProtocol(incentiveSystem, issuerKey.getVerificationKey());
        SpendDeductProtocol.SpendDeductProtocolInstance spendUserInstance = spendProtocol.instantiateUser(k, token);
        addTimeToUser();

        countTowards(false);
        startStopwatch();
        SpendDeductProtocol spendProtocol2 = new SpendDeductProtocol(incentiveSystem, issuerKey.getVerificationKey());
        SpendDeductProtocol.SpendDeductProtocolInstance spendProviderInstance = spendProtocol2.instantiateProvider(k, token.dsid, issuerKey.getSigningKey());
        addTimeToProvider();

        runProtocol(spendUserInstance, spendProviderInstance);

        countTowards(true);
        startStopwatch();
        token = spendUserInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();

        countTowards(false);
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
            countTowards(isUsersTurn);
            startStopwatch();
            message = currentParty.nextMessage(message);
            addTimeTo(isUsersTurn);

            isUsersTurn = !isUsersTurn;
            currentParty = isUsersTurn ? userInstance : providerInstance;
        } while (!userInstance.hasTerminated() || !providerInstance.hasTerminated());
    }

    public void countTowards(boolean toUser) {
        if (incentiveSystem.group instanceof DebugBilinearGroup) {
            ((DebugBilinearGroup) incentiveSystem.group).setBucket(toUser ? "user" : "provider");
        }
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
            benchmark.setup(new MclBilinearGroup());
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

        //Count user ops
        //TODO add ability to count towards buckets
        try {
            Benchmark benchmark = new Benchmark();
            DebugBilinearGroup bilinearGroup = new DebugBilinearGroup(new MclBilinearGroup().size(), BilinearGroup.Type.TYPE_3);
            benchmark.setup(bilinearGroup);

            bilinearGroup.resetCounters("user");
            bilinearGroup.resetCounters("provider");
            benchmark.join();
            System.out.println("Join User");
            System.out.println(bilinearGroup.formatCounterData("user"));
            System.out.println();
            System.out.println("Join Provider");
            System.out.println(bilinearGroup.formatCounterData("provider"));
            System.out.println();

            bilinearGroup.resetCounters("user");
            bilinearGroup.resetCounters("provider");
            benchmark.earn(100);
            System.out.println("Earn User");
            System.out.println(bilinearGroup.formatCounterData("user"));
            System.out.println();
            System.out.println("Earn Provider");
            System.out.println(bilinearGroup.formatCounterData("provider"));
            System.out.println();

            bilinearGroup.resetCounters("user");
            bilinearGroup.resetCounters("provider");
            benchmark.spend(30);
            System.out.println("Spend User");
            System.out.println(bilinearGroup.formatCounterData("user"));
            System.out.println();
            System.out.println("Spend Provider");
            System.out.println(bilinearGroup.formatCounterData("provider"));
            System.out.println();
        } catch (RuntimeException e) {
            e.printStackTrace();
        }

    }
}
