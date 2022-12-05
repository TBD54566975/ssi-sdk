# Employment Verification Use Case

## Introduction

This is a full example flow of a student (holder), getting a Verifiable Credential from an
university (issuer), and then using that credential to apply for a job with the company (verifier).
The verifier will then authorize the credential, if it trusts the source, and
grant approval to the application process.

```mermaid
    graph TD
        %%{init: {'theme': 'neutral' } }%%
        direction LR
        Holder[Student]
        Verifier[Employer]
        Issuer[University]

        Issuer -->|Sends credential to holder saying the holder graduated from the university| Holder
        Verifier -->|Sends a request to prove the holder graduated from the university| Holder
        Holder -->|Sends a claim asserting that they did graduate from the university| Verifier

   ```

## Communication Diagram

```mermaid
sequenceDiagram
    %%{init: {'theme': 'neutral' } }%%
    Issuer->>Holder: Here is a VC with saying you graduated from here
    Note right of Holder: Holder stores in wallet
    Verifier->>Holder: Sends a Presentation Request showing a claim that they graduated from a trusted university.
    Holder->>Verifier: Prepares a Presentation Submission with the claims asserted.
    Note left of Verifier: Validates that the claim is from a trusted entity that passes the criteria. If approved, asserts confirmation of approval.
```

## Steps

1. Holder, Issuer, and Verifier all are granted wallets and they are initialized.
2. Issuer sends a VC to the holder saying they graduated from the University. It has additionally information such as
   the degree they graduated with.
3. Holder will store the VC in their wallet, "owning" the VC.
4. The Verifier will request to validate the Holder graduated from a university using a Presentation Request.
5. The Holder will respond with a Verified Submission, asserting the claim that they graduated from the university.
6. If the Verifier trusts the university, they will authorize the next step. If not, they will reject the application.

## Output

An example of the output is shown below:

![flow.gif](flow.gif)
