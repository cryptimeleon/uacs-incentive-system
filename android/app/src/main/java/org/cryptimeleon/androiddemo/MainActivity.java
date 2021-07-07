package org.cryptimeleon.androiddemo;

import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;
import org.cryptimeleon.uacs.CreditEarnProtocol;
import org.cryptimeleon.uacs.DoubleSpendTag;
import org.cryptimeleon.uacs.IssueJoinProtocol;
import org.cryptimeleon.uacs.KeyPair;
import org.cryptimeleon.uacs.SpendDeductProtocol;
import org.cryptimeleon.uacs.Token;
import org.cryptimeleon.uacs.UacsIncentiveSystem;

import java.math.BigInteger;

public class MainActivity extends AppCompatActivity {

    private TextView textViewResult;
    private Button button;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Load herumi/mcl for faster pairings
        System.loadLibrary("mcljava");

        textViewResult = findViewById(R.id.textview_result);
        button = findViewById(R.id.button_start);
        button.setOnClickListener(v -> computePairing());
    }

    /**
     * Setup, compute and verify a Pointcheval-Sanders signature.
     * Implements the pairing tutorial on https://cryptimeleon.github.io/getting-started/pairing-tutorial.html.
     * Sends ui updates to the UI thread since the computations are performed in a background thread.
     */
    private void computePairing() {
        button.setEnabled(false);
        textViewResult.setText("");

        AsyncTask.execute(() -> {
            appendToResultTextView("Starting computation...");

            try {
                setup();
                int iterations = 100;

                resetTimes();
                for (int i = 0; i < iterations; i++)
                    join();
                System.out.println("Join");
                appendToResultTextView("Join");
                printTimes(iterations);

                resetTimes();
                for (int i = 0; i < iterations; i++)
                    earn(100);
                System.out.println("Earn");
                appendToResultTextView("Earn");
                printTimes(iterations);

                resetTimes();
                for (int i = 0; i < iterations; i++)
                    spend(20);
                System.out.println("Spend");
                appendToResultTextView("Spend");
                printTimes(iterations);
            } catch (RuntimeException e) {
                e.printStackTrace();
            }

            runOnUiThread(() -> button.setEnabled(true));
        });
    }

    /**
     * Appends a string to the textViewResult textview and appends a line break.
     * Uses runOnUiThread since it is supposed to be used from a background thread.
     *
     * @param linesToAppend the string to add
     */
    private void appendToResultTextView(String linesToAppend) {
        runOnUiThread(() -> textViewResult.append(linesToAppend + "\n\n"));
    }

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
        appendToResultTextView("User: "+userTime/numberIterations/1000000 + " ms");
        appendToResultTextView("Provider: "+providerTime/numberIterations/1000000 + " ms");
    }

}