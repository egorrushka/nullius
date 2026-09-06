"""Integrity check against the last agreed-good tree.

The set of files to check is whatever git tracks, minus a short EXCLUDE of
files that cannot or should not be hash-pinned. Sourcing the set from git —
not from a directory walk — is deliberate: an ignored or untracked file
(vendor/, desktop.ini, a scratch note) can never silently enter the
manifest, and a walk that drifts from the tree can never quietly pin junk.
A file counts only once git knows about it.

For every such file two hashes are compared against the manifest:

  DAMAGED   content differs, and not only in line endings — look here first
  EOL-ONLY  content is identical, only CRLF-vs-LF differs — usually harmless,
            but a .ccert converted to CRLF changes its digest, so it matters
            for certificates; .gitattributes is meant to prevent this
  MISSING   the manifest had it and the working tree does not
  EXTRA     git tracks a file the manifest did not record

The manifest is the REFERENCE dict below. It is regenerated, never edited by
hand: run regen_manifest.py, which rebuilds it from this same git-tracked set
and splices it back in. check_integrity.py excludes itself because it cannot
hash-pin the bytes a regeneration rewrites.

Run from E:\\EK:  python check_integrity.py
"""

import hashlib
import pathlib
import subprocess
import sys

# Full posix paths dropped from the tracked set. check_integrity.py rewrites
# itself on every regeneration; verifier.generated.js is a build product.
# Everything else git tracks is pinned — including Cargo.lock (a dependency
# pin a trust tool should watch) and the wasm (an independent verification
# path whose bytes matter).
EXCLUDE = {
    "check_integrity.py",
    "web/src/verifier.generated.js",
}


def tracked_paths(root: pathlib.Path) -> list:
    """What git tracks under root, in posix form, minus EXCLUDE."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(root), capture_output=True, check=True,
        ).stdout
    except FileNotFoundError as e:
        raise SystemExit("git is not on PATH; this checker needs git to "
                         "learn which files are tracked") from e
    except subprocess.CalledProcessError as e:
        raise SystemExit("`git ls-files` failed; run this inside the E:\\EK "
                         "git working tree") from e
    paths = []
    for chunk in out.split(b"\x00"):
        if not chunk:
            continue
        rel = chunk.decode("utf-8")
        if rel in EXCLUDE:
            continue
        paths.append(rel)
    return paths


REFERENCE = {
".gitattributes": {
"norm": "a570454d535ae6b84edae2827beeec62611d86bfec271680a2c13cd00faef367",
"raw": "a570454d535ae6b84edae2827beeec62611d86bfec271680a2c13cd00faef367"
},
".github/workflows/ci.yml": {
"norm": "73b551abe067c61625054c5f6c09548c66df63b4a217d0c7e341793c2ea1a529",
"raw": "73b551abe067c61625054c5f6c09548c66df63b4a217d0c7e341793c2ea1a529"
},
".github/workflows/fuzz.yml": {
"norm": "9d36269fd30c8ee8405351d903c0c0590f5e61553679461ad43ea81948335b58",
"raw": "9d36269fd30c8ee8405351d903c0c0590f5e61553679461ad43ea81948335b58"
},
".gitignore": {
"norm": "c99ae21e8c51edf1e2f76a0a45b6ac66dd27456a2bd813a6beb55c3db0c394d7",
"raw": "c99ae21e8c51edf1e2f76a0a45b6ac66dd27456a2bd813a6beb55c3db0c394d7"
},
"CONTRIBUTING.md": {
"norm": "af091853cccf7a058533655327b20fb7792ae88600cda79d593622cf1772c10b",
"raw": "af091853cccf7a058533655327b20fb7792ae88600cda79d593622cf1772c10b"
},
"LICENSE": {
"norm": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
"raw": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
},
"NOTICE": {
"norm": "f171ccd50ebca368f59f2e6d775b23722ffe9da6926de6dd6ae61c13407585da",
"raw": "f171ccd50ebca368f59f2e6d775b23722ffe9da6926de6dd6ae61c13407585da"
},
"README.md": {
"norm": "53afb16009e373d6985d803c23d8732fb9cd14f5bac8ef7a5a45688518829cb6",
"raw": "53afb16009e373d6985d803c23d8732fb9cd14f5bac8ef7a5a45688518829cb6"
},
"core/__init__.py": {
"norm": "e944dbd668ec43459f2b5f32b948d3dfae9836aa18208480e85e84bc17cb70ff",
"raw": "e944dbd668ec43459f2b5f32b948d3dfae9836aa18208480e85e84bc17cb70ff"
},
"core/backends/README.md": {
"norm": "ab99d3781da7217bd6d930941870da49fe0a963c23b580f058a8e92574172843",
"raw": "ab99d3781da7217bd6d930941870da49fe0a963c23b580f058a8e92574172843"
},
"core/backends/__init__.py": {
"norm": "2c34536cebcfc0d3d55dc2ab8c3e82225b0c3ccd4a9c1072e9f0a488ef3ad41f",
"raw": "2c34536cebcfc0d3d55dc2ab8c3e82225b0c3ccd4a9c1072e9f0a488ef3ad41f"
},
"core/backends/gp.py": {
"norm": "d0b286c7c248cddd0d7eb4ad6f936ba688cff2c92cc05f9ee487c6bff95755dc",
"raw": "d0b286c7c248cddd0d7eb4ad6f936ba688cff2c92cc05f9ee487c6bff95755dc"
},
"core/backends/gp_fp2.py": {
"norm": "eac4d5161a91fd043a2024ffacbfc427d5087023034b767b3e63f49ee1a31683",
"raw": "eac4d5161a91fd043a2024ffacbfc427d5087023034b767b3e63f49ee1a31683"
},
"core/bundle/__init__.py": {
"norm": "07d8712dea66bf8254530f3263273eb17f66ebcc2cb2635e6ab6865b222c8a93",
"raw": "07d8712dea66bf8254530f3263273eb17f66ebcc2cb2635e6ab6865b222c8a93"
},
"core/bundle/assembly.py": {
"norm": "990fae55bdee769191a216e068d4d2f8351638bc0a71ee370520d8a72f901085",
"raw": "990fae55bdee769191a216e068d4d2f8351638bc0a71ee370520d8a72f901085"
},
"core/bundle/builder.py": {
"norm": "dd38f2fb36cdf1b5af9d7d5e933c21a92efcff86dc5392131a6d1cda8144e5d3",
"raw": "dd38f2fb36cdf1b5af9d7d5e933c21a92efcff86dc5392131a6d1cda8144e5d3"
},
"core/bundle/canonical.py": {
"norm": "b84eed59ae8153b1511f44c28f67210ac88ae8b2d238f0b1c01bd77d877de91c",
"raw": "b84eed59ae8153b1511f44c28f67210ac88ae8b2d238f0b1c01bd77d877de91c"
},
"core/bundle/model.py": {
"norm": "465c6b70c1bc3c7434c6b98e8ad031e7a61f4004c4998b9c0f3640a051590e95",
"raw": "465c6b70c1bc3c7434c6b98e8ad031e7a61f4004c4998b9c0f3640a051590e95"
},
"core/bundle/pairing.py": {
"norm": "c39eeb9792e501ef0222438594ee03ab204163b49dab32a1e53572a892b2b67b",
"raw": "c39eeb9792e501ef0222438594ee03ab204163b49dab32a1e53572a892b2b67b"
},
"core/claims/__init__.py": {
"norm": "1382acf8fd2f52dcaf0974cbd0505f45a217045d919392044d453e84b6078495",
"raw": "1382acf8fd2f52dcaf0974cbd0505f45a217045d919392044d453e84b6078495"
},
"core/claims/elimination.py": {
"norm": "500349fea59ddc50052bf23f7074c44b116fe730a7983edc2f9d7c9fd45c40b2",
"raw": "500349fea59ddc50052bf23f7074c44b116fe730a7983edc2f9d7c9fd45c40b2"
},
"core/claims/family.py": {
"norm": "043ec84b7c507926a54715a7c6936f4dc41c32ae69c9a81d5c3337fbf9077bc1",
"raw": "043ec84b7c507926a54715a7c6936f4dc41c32ae69c9a81d5c3337fbf9077bc1"
},
"core/claims/models.py": {
"norm": "491b71f095d57b4dca744bfa05becb35b2e34b6988f112707e571f5f997a7c97",
"raw": "491b71f095d57b4dca744bfa05becb35b2e34b6988f112707e571f5f997a7c97"
},
"core/claims/point_order.py": {
"norm": "c79aaa2a776f6ac0b24d192873a45678aa1cc59bf255323709a81f3a1da6c3f0",
"raw": "c79aaa2a776f6ac0b24d192873a45678aa1cc59bf255323709a81f3a1da6c3f0"
},
"core/claims/rigidity.py": {
"norm": "35957437813125fe8bd5f2d25f108323903ff67604e34c43808cfb3596a9bb52",
"raw": "35957437813125fe8bd5f2d25f108323903ff67604e34c43808cfb3596a9bb52"
},
"core/claims/twist.py": {
"norm": "e423e909de0bd0eac5ebc4172f977ae0a269a3cbce355feca8a019aedfc92103",
"raw": "e423e909de0bd0eac5ebc4172f977ae0a269a3cbce355feca8a019aedfc92103"
},
"core/field/__init__.py": {
"norm": "fb8734c54347c2cc4b14b4c0752011435d9cb0da0b6c50fcb27b0a58c5f1d9bf",
"raw": "fb8734c54347c2cc4b14b4c0752011435d9cb0da0b6c50fcb27b0a58c5f1d9bf"
},
"core/field/fp.py": {
"norm": "90c44c959cd4ab6a8ac724a81d870b6a9bff7edfcd300a169c1dbe5ba31b2b69",
"raw": "90c44c959cd4ab6a8ac724a81d870b6a9bff7edfcd300a169c1dbe5ba31b2b69"
},
"core/field/fp2.py": {
"norm": "4e40349cd935a14b62bdc26bd1430153c67f7fe58589f6677231b9614d8a2445",
"raw": "4e40349cd935a14b62bdc26bd1430153c67f7fe58589f6677231b9614d8a2445"
},
"core/field/fp4.py": {
"norm": "3512292fb8eaccc2cb01e5f1106e7bfd8630a359db7ad9a61983f06dac68f3f5",
"raw": "3512292fb8eaccc2cb01e5f1106e7bfd8630a359db7ad9a61983f06dac68f3f5"
},
"core/field/order.py": {
"norm": "64cd202a26088073f960305cf6106b0dc8f7614e3a39ac64dcf4fd8619cbff01",
"raw": "64cd202a26088073f960305cf6106b0dc8f7614e3a39ac64dcf4fd8619cbff01"
},
"core/policy/__init__.py": {
"norm": "3cc00a9663f1c8a9116ebc7b79a703b1665e0e3bfab76fe16c4cdbecb08cc32c",
"raw": "3cc00a9663f1c8a9116ebc7b79a703b1665e0e3bfab76fe16c4cdbecb08cc32c"
},
"core/policy/engine.py": {
"norm": "d61ef7caf02035fa3db8a904dfdff40c729a56815797bf924a04b0d7a21f1b21",
"raw": "d61ef7caf02035fa3db8a904dfdff40c729a56815797bf924a04b0d7a21f1b21"
},
"core/policy/policies/README.md": {
"norm": "61f57f011d807fb0070731fcbe1931fc8da3fe764f32b96b84cb9185886e6e41",
"raw": "61f57f011d807fb0070731fcbe1931fc8da3fe764f32b96b84cb9185886e6e41"
},
"core/policy/policies/glv-endomorphism.yaml": {
"norm": "3bc1b9a457162f397dac82b408d2d3f49d4898bb91d7bdfc2263f9d21394b283",
"raw": "3bc1b9a457162f397dac82b408d2d3f49d4898bb91d7bdfc2263f9d21394b283"
},
"core/policy/policies/pairing-security-pre-tnfs.yaml": {
"norm": "64b9a52bc734a142e24583b057f7cdfde3fa3eda325e4fb8a8b0ebb9f0be2438",
"raw": "64b9a52bc734a142e24583b057f7cdfde3fa3eda325e4fb8a8b0ebb9f0be2438"
},
"core/policy/policies/pairing-security-tnfs-192.yaml": {
"norm": "f4ff179db40b66aa864c7de551a4edfbb9fcae85169a5b65f1d715527008bf67",
"raw": "f4ff179db40b66aa864c7de551a4edfbb9fcae85169a5b65f1d715527008bf67"
},
"core/policy/policies/pairing-security-tnfs-2016.yaml": {
"norm": "ef8f7df65eb4938bde2d69affbe90c90934285224d2326a18a665d639b395451",
"raw": "ef8f7df65eb4938bde2d69affbe90c90934285224d2326a18a665d639b395451"
},
"core/policy/policies/pairing-suitability.yaml": {
"norm": "90992817c7a441b2b97171f0b7ee3a26119d297f6d5d0a9e21001adb447bc076",
"raw": "90992817c7a441b2b97171f0b7ee3a26119d297f6d5d0a9e21001adb447bc076"
},
"core/policy/policies/safecurves-2024.yaml": {
"norm": "fd34c6bb60e589fa0b74faaae27e3097d11dfaffc895e318ad8cad8f562d4cc6",
"raw": "fd34c6bb60e589fa0b74faaae27e3097d11dfaffc895e318ad8cad8f562d4cc6"
},
"core/policy/policies/snark-suitability.yaml": {
"norm": "3203531fabb87aa449a73300e41d1192ab5089de7a452307d1196208cca8af1f",
"raw": "3203531fabb87aa449a73300e41d1192ab5089de7a452307d1196208cca8af1f"
},
"docs/DESIGN.md": {
"norm": "0fca58e01a448b2b4f2285d59ca4175bdab6b81edbc960d284a6f75e6befb001",
"raw": "0fca58e01a448b2b4f2285d59ca4175bdab6b81edbc960d284a6f75e6befb001"
},
"docs/OPEN_QUESTION_high_degree_extensions.md": {
"norm": "f180e3bdac998fc2ec85ff6b23c37597c9be3322bb71bbe6022d272807b767b2",
"raw": "f180e3bdac998fc2ec85ff6b23c37597c9be3322bb71bbe6022d272807b767b2"
},
"docs/ROADMAP.md": {
"norm": "15dfe6f87e026f306bbb69cb98f6e678890121dcd5159f5563e00d9c91be4c89",
"raw": "15dfe6f87e026f306bbb69cb98f6e678890121dcd5159f5563e00d9c91be4c89"
},
"docs/dossier.png": {
"norm": "16272d5b190d8481854afbc61d330ca2046c3d7a8179e0d15554f36175b83853",
"raw": "c36c782fac933bda0093d0861a9a170de5d3e1d98c8ad9873e3cd1737a8d8719"
},
"docs/security-model.md": {
"norm": "c64df96672caabfbdc52b4670ccbabaa393602a74d068e838d0e1954b4ad0bf2",
"raw": "c64df96672caabfbdc52b4670ccbabaa393602a74d068e838d0e1954b4ad0bf2"
},
"docs/ukraine_flag.gif": {
"norm": "f30211ca6b4492ee350863469bde3bf9a03cffa97f717d4f01ca0076213086da",
"raw": "e4cab823f1eb267c11a6caca2b8322ca6ffab4b51a5adaa6106bdd83bbdc12ef"
},
"pyproject.toml": {
"norm": "596019136060a7530de6cc686e88a76c69c63993b901312cf8f9a48165d40b03",
"raw": "596019136060a7530de6cc686e88a76c69c63993b901312cf8f9a48165d40b03"
},
"regen_manifest.py": {
"norm": "ef1989b8f9e9d3b23a4d40b8748a5382e7faf112f2192c58312cfb00cb4c5dc4",
"raw": "ef1989b8f9e9d3b23a4d40b8748a5382e7faf112f2192c58312cfb00cb4c5dc4"
},
"rust-toolchain.toml": {
"norm": "9dfb20571471692a62e37d1f2b81f9d923211b8e6317a73663bf80fae9052452",
"raw": "9dfb20571471692a62e37d1f2b81f9d923211b8e6317a73663bf80fae9052452"
},
"spec/canonical-encoding.md": {
"norm": "30aa8a7d91c6c043aac7bab7c145d864347a1fe1662c92446413e6807acf4726",
"raw": "30aa8a7d91c6c043aac7bab7c145d864347a1fe1662c92446413e6807acf4726"
},
"spec/ccert-v0.md": {
"norm": "cc2f2c87955c76bfd5306f522230dbfc86b9aee1473c2ca9556f91e97f168c2f",
"raw": "cc2f2c87955c76bfd5306f522230dbfc86b9aee1473c2ca9556f91e97f168c2f"
},
"spec/claims/README.md": {
"norm": "2be1db1e124322f27d98f0f1b48642272f49a7eaeaef0c2f2e263250c95540c2",
"raw": "2be1db1e124322f27d98f0f1b48642272f49a7eaeaef0c2f2e263250c95540c2"
},
"spec/vectors/invalid/.gitkeep": {
"norm": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
"raw": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
},
"spec/vectors/invalid/README.md": {
"norm": "da7385f77b45d4a933a6aaa334329e0bcd67fd3139dabd332ce8f60e2de0df33",
"raw": "da7385f77b45d4a933a6aaa334329e0bcd67fd3139dabd332ce8f60e2de0df33"
},
"spec/vectors/invalid/asserts-with-an-unread-field.ccert": {
"norm": "a236cec76a52058d7ee3fc954cca1ec4bf620e7cba6806979bea67212ad34b81",
"raw": "a236cec76a52058d7ee3fc954cca1ec4bf620e7cba6806979bea67212ad34b81"
},
"spec/vectors/invalid/asserts-with-an-unread-field.expect": {
"norm": "9d32044000c6d0fe5dfcba96841305c99bb19fcbfa83c2396dfe187cc09d1378",
"raw": "9d32044000c6d0fe5dfcba96841305c99bb19fcbfa83c2396dfe187cc09d1378"
},
"spec/vectors/invalid/asserts-with-an-unread-field.why": {
"norm": "e6f0ff5862b62a33ebeb9649f128d3726dd540750b0777e3e5c6589de95927ef",
"raw": "e6f0ff5862b62a33ebeb9649f128d3726dd540750b0777e3e5c6589de95927ef"
},
"spec/vectors/invalid/broken-evidence-hash.ccert": {
"norm": "7e70721604a3848d0a5142ce8dde962c4601487cea1180bf91c269f48e079850",
"raw": "7e70721604a3848d0a5142ce8dde962c4601487cea1180bf91c269f48e079850"
},
"spec/vectors/invalid/broken-evidence-hash.expect": {
"norm": "4e5e494fa316ffc82b8252b23524f1433639858267d641c1217059dc4403e045",
"raw": "4e5e494fa316ffc82b8252b23524f1433639858267d641c1217059dc4403e045"
},
"spec/vectors/invalid/broken-evidence-hash.why": {
"norm": "5409ed9447439c5b693ae3b45247d28b8bde2c75d81607edaa9b7b6d411e365c",
"raw": "5409ed9447439c5b693ae3b45247d28b8bde2c75d81607edaa9b7b6d411e365c"
},
"spec/vectors/invalid/byte-order-mark.ccert": {
"norm": "3ba64a31918cbb36ebbef1bf27cd68dd850a2d56feaf565e49675711ae0c4920",
"raw": "3ba64a31918cbb36ebbef1bf27cd68dd850a2d56feaf565e49675711ae0c4920"
},
"spec/vectors/invalid/byte-order-mark.expect": {
"norm": "18babcb8a6ceadbc71560c4a18758d446781d0c44c53a8fb21917146b4217908",
"raw": "18babcb8a6ceadbc71560c4a18758d446781d0c44c53a8fb21917146b4217908"
},
"spec/vectors/invalid/byte-order-mark.why": {
"norm": "c3070f07549d0ca6ee9904dffdfc0e0a9a690c0d7094e69eafbecd503dffb482",
"raw": "c3070f07549d0ca6ee9904dffdfc0e0a9a690c0d7094e69eafbecd503dffb482"
},
"spec/vectors/invalid/candidate-source.ccert": {
"norm": "277f511580c8e5ffcb69dd1d98a2b26f97d76879787c31e9bf8ae11684dab3aa",
"raw": "277f511580c8e5ffcb69dd1d98a2b26f97d76879787c31e9bf8ae11684dab3aa"
},
"spec/vectors/invalid/candidate-source.expect": {
"norm": "1e81270f1a47dce22a2e4985250c74b2e3374443734f1492b03ea2cd2af4ec48",
"raw": "1e81270f1a47dce22a2e4985250c74b2e3374443734f1492b03ea2cd2af4ec48"
},
"spec/vectors/invalid/candidate-source.why": {
"norm": "df47c80f64afbb090200aa04fbe3b1525e00e401605da2fd2b49b2fd87f3499b",
"raw": "df47c80f64afbb090200aa04fbe3b1525e00e401605da2fd2b49b2fd87f3499b"
},
"spec/vectors/invalid/chain-for-another-number.ccert": {
"norm": "858a8e3fda1a4000d0075c7451a9614f96f071888b0444e6ebcd49df756169e2",
"raw": "858a8e3fda1a4000d0075c7451a9614f96f071888b0444e6ebcd49df756169e2"
},
"spec/vectors/invalid/chain-for-another-number.expect": {
"norm": "3b653cb6dd5502aa13651faeadc02b30c59dc9fff1d05644719d7ebeeafa82eb",
"raw": "3b653cb6dd5502aa13651faeadc02b30c59dc9fff1d05644719d7ebeeafa82eb"
},
"spec/vectors/invalid/chain-for-another-number.why": {
"norm": "6db80ba09127d36d85b226f6b0a187e620c37cf3314206819749d53b41c49e45",
"raw": "6db80ba09127d36d85b226f6b0a187e620c37cf3314206819749d53b41c49e45"
},
"spec/vectors/invalid/chain-step-with-an-unread-field.ccert": {
"norm": "8ad576942c3937be66cf3eb664edf811ec70f4ca34149a3d10484be3e7e919bf",
"raw": "8ad576942c3937be66cf3eb664edf811ec70f4ca34149a3d10484be3e7e919bf"
},
"spec/vectors/invalid/chain-step-with-an-unread-field.expect": {
"norm": "8fc9e5f0d98b85a066d1305cc429159d6f594e474b6e321d002e5c3e6e679f5f",
"raw": "8fc9e5f0d98b85a066d1305cc429159d6f594e474b6e321d002e5c3e6e679f5f"
},
"spec/vectors/invalid/chain-step-with-an-unread-field.why": {
"norm": "3438aced719549e57236ebc6c7d29f59e87325e1774830d2bbe1398babd92e83",
"raw": "3438aced719549e57236ebc6c7d29f59e87325e1774830d2bbe1398babd92e83"
},
"spec/vectors/invalid/claim-with-an-unread-field.ccert": {
"norm": "f8e6e85ac5309db80406201cb35fe7a20a41b13be4e27b34c51a3e0ebdaed964",
"raw": "f8e6e85ac5309db80406201cb35fe7a20a41b13be4e27b34c51a3e0ebdaed964"
},
"spec/vectors/invalid/claim-with-an-unread-field.expect": {
"norm": "b052cd51020cb02681bc71c3d83a8887f402923ca17f6f91ae8a57df2da05276",
"raw": "b052cd51020cb02681bc71c3d83a8887f402923ca17f6f91ae8a57df2da05276"
},
"spec/vectors/invalid/claim-with-an-unread-field.why": {
"norm": "e4abe86aa9824776d4962467724d8d887bb212c17a9a4dff4e33a131c9e4cc1c",
"raw": "e4abe86aa9824776d4962467724d8d887bb212c17a9a4dff4e33a131c9e4cc1c"
},
"spec/vectors/invalid/degree-four-without-xi.ccert": {
"norm": "1e97ead977b8b559264fb0fa29201a6f4d813d14ff5bd601b35fd47267c95126",
"raw": "1e97ead977b8b559264fb0fa29201a6f4d813d14ff5bd601b35fd47267c95126"
},
"spec/vectors/invalid/degree-four-without-xi.expect": {
"norm": "92dfea11bdf49e59a694156159818976bf224062c7e45df2e12f20bab83dcdc0",
"raw": "92dfea11bdf49e59a694156159818976bf224062c7e45df2e12f20bab83dcdc0"
},
"spec/vectors/invalid/degree-four-without-xi.why": {
"norm": "1fcf4ad74a0fe078d96d833c4097214b2b0c4122ac176f68b00539f255a50f60",
"raw": "1fcf4ad74a0fe078d96d833c4097214b2b0c4122ac176f68b00539f255a50f60"
},
"spec/vectors/invalid/elimination-on-the-base-curve.ccert": {
"norm": "41649b2181786053e30651a7b21900a0cbf6619f2872a88e48d84f74a134dd89",
"raw": "41649b2181786053e30651a7b21900a0cbf6619f2872a88e48d84f74a134dd89"
},
"spec/vectors/invalid/elimination-on-the-base-curve.expect": {
"norm": "5bd00878f7b6d7488a68d56d8a6f5bf9fba8864dad5cc1b18387c9f4b9a1d8c9",
"raw": "5bd00878f7b6d7488a68d56d8a6f5bf9fba8864dad5cc1b18387c9f4b9a1d8c9"
},
"spec/vectors/invalid/elimination-on-the-base-curve.why": {
"norm": "010849de55408338ec957eaaca1eeada320387a8fd2d27ffbb2476dfce85ca99",
"raw": "010849de55408338ec957eaaca1eeada320387a8fd2d27ffbb2476dfce85ca99"
},
"spec/vectors/invalid/elimination-point-off-curve.ccert": {
"norm": "0487afc00f353caf82a6732d05e18978e77d565ecd8f59150f43a12372a39885",
"raw": "0487afc00f353caf82a6732d05e18978e77d565ecd8f59150f43a12372a39885"
},
"spec/vectors/invalid/elimination-point-off-curve.expect": {
"norm": "55396436b4a461e4f0acc8a38053563abdf6bcc5afcb0be0b9dc9a75aa53b08f",
"raw": "55396436b4a461e4f0acc8a38053563abdf6bcc5afcb0be0b9dc9a75aa53b08f"
},
"spec/vectors/invalid/elimination-point-off-curve.why": {
"norm": "7ec70ee5173505414248ce2a8a41d61934c91c8517d1b01a80db48b5658be81b",
"raw": "7ec70ee5173505414248ce2a8a41d61934c91c8517d1b01a80db48b5658be81b"
},
"spec/vectors/invalid/elimination-useless-point.ccert": {
"norm": "cff62eae0b56847fee0ec70af1353cb396d90b365dde0dcf8b97904713b1b419",
"raw": "cff62eae0b56847fee0ec70af1353cb396d90b365dde0dcf8b97904713b1b419"
},
"spec/vectors/invalid/elimination-useless-point.expect": {
"norm": "340b7b9c089b242219cf029e5bc297d683da78ee29f8c1d87982d7b75fb8aefc",
"raw": "340b7b9c089b242219cf029e5bc297d683da78ee29f8c1d87982d7b75fb8aefc"
},
"spec/vectors/invalid/elimination-useless-point.why": {
"norm": "5713b79c92f9e26a3ef4e0e1ef4ca69ae58e9d9c4aea4cb8c3fbbfbaa1f03408",
"raw": "5713b79c92f9e26a3ef4e0e1ef4ca69ae58e9d9c4aea4cb8c3fbbfbaa1f03408"
},
"spec/vectors/invalid/elimination-without-points.ccert": {
"norm": "b9c333a88fe4a8f1a77e908ab9207eda25db965b38db273980f6b4dd291f4b21",
"raw": "b9c333a88fe4a8f1a77e908ab9207eda25db965b38db273980f6b4dd291f4b21"
},
"spec/vectors/invalid/elimination-without-points.expect": {
"norm": "f99668be6feb51c79e556c0508b4a68266bc98410868680369462bf280686906",
"raw": "f99668be6feb51c79e556c0508b4a68266bc98410868680369462bf280686906"
},
"spec/vectors/invalid/elimination-without-points.why": {
"norm": "46b986f87b8641e811df65179a47c583596a086fb5691954ed684c78422855bd",
"raw": "46b986f87b8641e811df65179a47c583596a086fb5691954ed684c78422855bd"
},
"spec/vectors/invalid/elimination-wrong-survivor.ccert": {
"norm": "a1ac76df1931a98385600e93b0f97f3fd3adb2f6ad747e271c4720a913f3d150",
"raw": "a1ac76df1931a98385600e93b0f97f3fd3adb2f6ad747e271c4720a913f3d150"
},
"spec/vectors/invalid/elimination-wrong-survivor.expect": {
"norm": "eed1375feb2320ae9f7c707a5b6161fad4dd34599ef1ec72c9d6e926a52a4abc",
"raw": "eed1375feb2320ae9f7c707a5b6161fad4dd34599ef1ec72c9d6e926a52a4abc"
},
"spec/vectors/invalid/elimination-wrong-survivor.why": {
"norm": "f8365838444ac1e16b36ce4b92ee875faee7ffc25b2360b24d7a397ed136c6f0",
"raw": "f8365838444ac1e16b36ce4b92ee875faee7ffc25b2360b24d7a397ed136c6f0"
},
"spec/vectors/invalid/empty-key.ccert": {
"norm": "58a874cf67849f36da770b3c01ef2c20f8555b94c72f6863cee2bf9cd491c6f4",
"raw": "58a874cf67849f36da770b3c01ef2c20f8555b94c72f6863cee2bf9cd491c6f4"
},
"spec/vectors/invalid/empty-key.expect": {
"norm": "b8b149e070d7d3c303d3606b90024bb75f71d8d76ff8be315cc58dc0e266288c",
"raw": "b8b149e070d7d3c303d3606b90024bb75f71d8d76ff8be315cc58dc0e266288c"
},
"spec/vectors/invalid/empty-key.why": {
"norm": "f3172a3c0e50bccd466dfe5e0f6aa1459ee65d15ed5413680a737cd0adb3b18a",
"raw": "f3172a3c0e50bccd466dfe5e0f6aa1459ee65d15ed5413680a737cd0adb3b18a"
},
"spec/vectors/invalid/escaped-solidus.ccert": {
"norm": "eef59c99428dddd09eab684b636e540a8a1adaf35a292eb75cfb34f677758683",
"raw": "eef59c99428dddd09eab684b636e540a8a1adaf35a292eb75cfb34f677758683"
},
"spec/vectors/invalid/escaped-solidus.expect": {
"norm": "6f45732e747c3082bc666646e4b0cf46594be54f866815c576403a8c93e50851",
"raw": "6f45732e747c3082bc666646e4b0cf46594be54f866815c576403a8c93e50851"
},
"spec/vectors/invalid/escaped-solidus.why": {
"norm": "ea7bad0ca42f2a1f2cb1f9d56d269d28cd97f50fa515db0da4db7c114712b0d5",
"raw": "ea7bad0ca42f2a1f2cb1f9d56d269d28cd97f50fa515db0da4db7c114712b0d5"
},
"spec/vectors/invalid/evidence-with-an-unread-field.ccert": {
"norm": "9f47cf2a15d6e1bb108317f48cc2c3738c985b8ffae4a291216e364cc772e7d4",
"raw": "9f47cf2a15d6e1bb108317f48cc2c3738c985b8ffae4a291216e364cc772e7d4"
},
"spec/vectors/invalid/evidence-with-an-unread-field.expect": {
"norm": "69679365804b4be863f00b25c2e36792b4620e2598e7b9d5447f2939cee966da",
"raw": "69679365804b4be863f00b25c2e36792b4620e2598e7b9d5447f2939cee966da"
},
"spec/vectors/invalid/evidence-with-an-unread-field.why": {
"norm": "8c200994dbbbfc80686e46f29499c5b28dca688b5e772376edba3c03429eed01",
"raw": "8c200994dbbbfc80686e46f29499c5b28dca688b5e772376edba3c03429eed01"
},
"spec/vectors/invalid/factor-entry-with-an-unread-field.ccert": {
"norm": "b582e3dde6169c364cef2ff9c53a884364fac1fa9289392c66cd6427ac746cae",
"raw": "b582e3dde6169c364cef2ff9c53a884364fac1fa9289392c66cd6427ac746cae"
},
"spec/vectors/invalid/factor-entry-with-an-unread-field.expect": {
"norm": "7d9e8d2ba92d84729a53ec0195862e8ba739b54ba3a256e27bd1fe63e7d72596",
"raw": "7d9e8d2ba92d84729a53ec0195862e8ba739b54ba3a256e27bd1fe63e7d72596"
},
"spec/vectors/invalid/factor-entry-with-an-unread-field.why": {
"norm": "e514bf91385f7905ee1c8561a830ab991a1f0758add78d606039e4a81b1a9353",
"raw": "e514bf91385f7905ee1c8561a830ab991a1f0758add78d606039e4a81b1a9353"
},
"spec/vectors/invalid/forbidden-key-byte.ccert": {
"norm": "92b890a365d901b21a7886ddd41a21877190960ffb4471217cf1ebcbe13ea77a",
"raw": "92b890a365d901b21a7886ddd41a21877190960ffb4471217cf1ebcbe13ea77a"
},
"spec/vectors/invalid/forbidden-key-byte.expect": {
"norm": "4e278a2c981362a4869f7835718e006008ad5918f78a34d69b45dbceff099ffe",
"raw": "4e278a2c981362a4869f7835718e006008ad5918f78a34d69b45dbceff099ffe"
},
"spec/vectors/invalid/forbidden-key-byte.why": {
"norm": "bb0982f1e8a04381a1c4b1f05da31639ff55aefa8c2c6f53f04f19974eac8473",
"raw": "bb0982f1e8a04381a1c4b1f05da31639ff55aefa8c2c6f53f04f19974eac8473"
},
"spec/vectors/invalid/foreign-curve.ccert": {
"norm": "83b638d522c4cfaed9b3e71a948167ec4a2113e294a4b6d9f914e8ae887e0984",
"raw": "83b638d522c4cfaed9b3e71a948167ec4a2113e294a4b6d9f914e8ae887e0984"
},
"spec/vectors/invalid/foreign-curve.expect": {
"norm": "39393ca169488139e050efcb2df6170c3f8965e19529f5a3727a5ecb05e04678",
"raw": "39393ca169488139e050efcb2df6170c3f8965e19529f5a3727a5ecb05e04678"
},
"spec/vectors/invalid/foreign-curve.why": {
"norm": "a80ea113edd0409de9f2db77e2f2fe7f83cfa8e6d537674fb29bb9d0220f9121",
"raw": "a80ea113edd0409de9f2db77e2f2fe7f83cfa8e6d537674fb29bb9d0220f9121"
},
"spec/vectors/invalid/giant-exponent.ccert": {
"norm": "69e676c16ee0e4138d618bdd8d69c36611d7ac8a786474b3216dc28d741ade60",
"raw": "69e676c16ee0e4138d618bdd8d69c36611d7ac8a786474b3216dc28d741ade60"
},
"spec/vectors/invalid/giant-exponent.expect": {
"norm": "04e7e53babb8d5a199cc06ccb163ade0b4ee5547bb1df3c5a415eb48bccb5df9",
"raw": "04e7e53babb8d5a199cc06ccb163ade0b4ee5547bb1df3c5a415eb48bccb5df9"
},
"spec/vectors/invalid/giant-exponent.why": {
"norm": "09564e7f8732630862eda77f01abeeeb99ee5ae425776b942a521687dc5abdf8",
"raw": "09564e7f8732630862eda77f01abeeeb99ee5ae425776b942a521687dc5abdf8"
},
"spec/vectors/invalid/json-number.ccert": {
"norm": "91ba6c13d824d0f3d38b92ab6318441456a0d60af602421cdb3f1942e5a1f1ab",
"raw": "91ba6c13d824d0f3d38b92ab6318441456a0d60af602421cdb3f1942e5a1f1ab"
},
"spec/vectors/invalid/json-number.expect": {
"norm": "a136183010d3abd430b7b3c9a4ef6fdb9a21b0c03dd8d2817c1c12b56a567580",
"raw": "a136183010d3abd430b7b3c9a4ef6fdb9a21b0c03dd8d2817c1c12b56a567580"
},
"spec/vectors/invalid/json-number.why": {
"norm": "db4da29288313bdbc8c82d9c7bd3b376f2ccd14cc5ff95b6418c456127ac2273",
"raw": "db4da29288313bdbc8c82d9c7bd3b376f2ccd14cc5ff95b6418c456127ac2273"
},
"spec/vectors/invalid/mismatched-cofactor.ccert": {
"norm": "620634058985d5d6c17f7076c488ac7805e7f456cf2a5de6c3e403000bbde60a",
"raw": "620634058985d5d6c17f7076c488ac7805e7f456cf2a5de6c3e403000bbde60a"
},
"spec/vectors/invalid/mismatched-cofactor.expect": {
"norm": "15594c2bdd9ade3cb4c23f65ff577a62ddc71d1a3c682a94d56b3bcdfc26b1e6",
"raw": "15594c2bdd9ade3cb4c23f65ff577a62ddc71d1a3c682a94d56b3bcdfc26b1e6"
},
"spec/vectors/invalid/mismatched-cofactor.why": {
"norm": "ba6271cff41b99e49a1747caa4aa9e0b628bdea8d6b67e60806a19f7a895e577",
"raw": "ba6271cff41b99e49a1747caa4aa9e0b628bdea8d6b67e60806a19f7a895e577"
},
"spec/vectors/invalid/non-minimal-unicode-escape.ccert": {
"norm": "6ec8877ed75194beee433bb7c7a194a0556c6968ba6ef44df00292d0aae8e436",
"raw": "6ec8877ed75194beee433bb7c7a194a0556c6968ba6ef44df00292d0aae8e436"
},
"spec/vectors/invalid/non-minimal-unicode-escape.expect": {
"norm": "22205c9c2034175931695b1702010f2939a6650a365061f34f3f532a311bdb2e",
"raw": "22205c9c2034175931695b1702010f2939a6650a365061f34f3f532a311bdb2e"
},
"spec/vectors/invalid/non-minimal-unicode-escape.why": {
"norm": "dde51a380d6b248dad3faf2292d647ce2fdba55a89f3c9c438fb81c6411f63b4",
"raw": "dde51a380d6b248dad3faf2292d647ce2fdba55a89f3c9c438fb81c6411f63b4"
},
"spec/vectors/invalid/order-unique-composite-n.ccert": {
"norm": "aedeb88867f1ed12887bba4b0cb38e1f58afc4ed764aec446b8a39978780ee41",
"raw": "aedeb88867f1ed12887bba4b0cb38e1f58afc4ed764aec446b8a39978780ee41"
},
"spec/vectors/invalid/order-unique-composite-n.expect": {
"norm": "3a20d108d1c57c7a39d04927aa1207aa199b97a1d39d2a4aed1b3de81f8a4a90",
"raw": "3a20d108d1c57c7a39d04927aa1207aa199b97a1d39d2a4aed1b3de81f8a4a90"
},
"spec/vectors/invalid/order-unique-composite-n.why": {
"norm": "ff6746f71e9afac8ad64d4cbb6e4dd5e3a8a6c579b243122acb95c7486d3525f",
"raw": "ff6746f71e9afac8ad64d4cbb6e4dd5e3a8a6c579b243122acb95c7486d3525f"
},
"spec/vectors/invalid/overstated-largest-factor.ccert": {
"norm": "9a6bd5187e0486f0bc52cf1fe7d798880045ace00ff62853bd40b25bfb99f80b",
"raw": "9a6bd5187e0486f0bc52cf1fe7d798880045ace00ff62853bd40b25bfb99f80b"
},
"spec/vectors/invalid/overstated-largest-factor.expect": {
"norm": "50def4487111e0cf7c06a7d97208a3f037e0968c646d4ff0e16132706860f1b2",
"raw": "50def4487111e0cf7c06a7d97208a3f037e0968c646d4ff0e16132706860f1b2"
},
"spec/vectors/invalid/overstated-largest-factor.why": {
"norm": "031f6aa5e6da40e54af21ef9c9e9da9c4bc7f2b81621a6abe60be5a9ddd16fdd",
"raw": "031f6aa5e6da40e54af21ef9c9e9da9c4bc7f2b81621a6abe60be5a9ddd16fdd"
},
"spec/vectors/invalid/overstated-two-adicity.ccert": {
"norm": "45bcc1036d2e0acebf954e03377001d3326e3cdc60abd3bade4e9bdeb3a95425",
"raw": "45bcc1036d2e0acebf954e03377001d3326e3cdc60abd3bade4e9bdeb3a95425"
},
"spec/vectors/invalid/overstated-two-adicity.expect": {
"norm": "1f8bafe27294dc34ee1396b850814b8045f36e67441eb0271126e6da208db5e8",
"raw": "1f8bafe27294dc34ee1396b850814b8045f36e67441eb0271126e6da208db5e8"
},
"spec/vectors/invalid/overstated-two-adicity.why": {
"norm": "c88ab2eaf4dda52ad1c9cab44d51918e9e8c6716a6d1c0ca0949bbfab8e14327",
"raw": "c88ab2eaf4dda52ad1c9cab44d51918e9e8c6716a6d1c0ca0949bbfab8e14327"
},
"spec/vectors/invalid/raw-control-byte.ccert": {
"norm": "99f7ba1f897a65781f708b2158bd301053238e119386a76d3743a60d90e8475d",
"raw": "99f7ba1f897a65781f708b2158bd301053238e119386a76d3743a60d90e8475d"
},
"spec/vectors/invalid/raw-control-byte.expect": {
"norm": "b197a82ce5de76830a004cfa24cbce71f8b8958d69a525a290247d6d12f91d7a",
"raw": "b197a82ce5de76830a004cfa24cbce71f8b8958d69a525a290247d6d12f91d7a"
},
"spec/vectors/invalid/raw-control-byte.why": {
"norm": "cb55982c84f6e786ed42f1c0279dd5b3b51532dab0b34ebbf0d3ab38bc89bb95",
"raw": "cb55982c84f6e786ed42f1c0279dd5b3b51532dab0b34ebbf0d3ab38bc89bb95"
},
"spec/vectors/invalid/reordered-keys.ccert": {
"norm": "f6e36960b4ffc01fdf08d0cfb49da0a82f1229c1f186fe1a4c7bb6c2dcda4894",
"raw": "f6e36960b4ffc01fdf08d0cfb49da0a82f1229c1f186fe1a4c7bb6c2dcda4894"
},
"spec/vectors/invalid/reordered-keys.expect": {
"norm": "602c5503220788cf7a25c8c9e952ecc9921870f109abdeb76966ea94502331ad",
"raw": "602c5503220788cf7a25c8c9e952ecc9921870f109abdeb76966ea94502331ad"
},
"spec/vectors/invalid/reordered-keys.why": {
"norm": "d273342bc93bcec9293c8e990efa9ac1951034adeef74ce008137874f28bab50",
"raw": "d273342bc93bcec9293c8e990efa9ac1951034adeef74ce008137874f28bab50"
},
"spec/vectors/invalid/singular-montgomery.ccert": {
"norm": "42d2edbe6faf40681e2cd6e971feb7d67892ea8507c0cedc3f4b1039c5c612bb",
"raw": "42d2edbe6faf40681e2cd6e971feb7d67892ea8507c0cedc3f4b1039c5c612bb"
},
"spec/vectors/invalid/singular-montgomery.expect": {
"norm": "295c5a970c29cdf3e76faee349ba8714a658aa2f1e4d0b0385b05054538b0e82",
"raw": "295c5a970c29cdf3e76faee349ba8714a658aa2f1e4d0b0385b05054538b0e82"
},
"spec/vectors/invalid/singular-montgomery.why": {
"norm": "49c322b56d6621cf34e601289f9fae86793c5b383c27f3d7452a191ffb25ff8e",
"raw": "49c322b56d6621cf34e601289f9fae86793c5b383c27f3d7452a191ffb25ff8e"
},
"spec/vectors/invalid/square-beta.ccert": {
"norm": "5bbcd3792785e249a71f111586f630984faf44b1ec1209663a27ae7221aa27b0",
"raw": "5bbcd3792785e249a71f111586f630984faf44b1ec1209663a27ae7221aa27b0"
},
"spec/vectors/invalid/square-beta.expect": {
"norm": "1b8a0a34fb84c0c9c1594a89a7270e14e2cf2c875d8f49f083a86044b364e576",
"raw": "1b8a0a34fb84c0c9c1594a89a7270e14e2cf2c875d8f49f083a86044b364e576"
},
"spec/vectors/invalid/square-beta.why": {
"norm": "83df9047bddcbe663e9fac31062d57c62bb713384eee8049eb0d97221f78339b",
"raw": "83df9047bddcbe663e9fac31062d57c62bb713384eee8049eb0d97221f78339b"
},
"spec/vectors/invalid/square-xi.ccert": {
"norm": "16b514df2335fddbba24e3d2b6bb5feb6a6b5ef6433df1ab3e0d9eac89b0ee14",
"raw": "16b514df2335fddbba24e3d2b6bb5feb6a6b5ef6433df1ab3e0d9eac89b0ee14"
},
"spec/vectors/invalid/square-xi.expect": {
"norm": "1b8a0a34fb84c0c9c1594a89a7270e14e2cf2c875d8f49f083a86044b364e576",
"raw": "1b8a0a34fb84c0c9c1594a89a7270e14e2cf2c875d8f49f083a86044b364e576"
},
"spec/vectors/invalid/square-xi.why": {
"norm": "40736f27cf06122dbab547e5d30d83f2535b9c53d1515cc8e15ae00a935d7b2d",
"raw": "40736f27cf06122dbab547e5d30d83f2535b9c53d1515cc8e15ae00a935d7b2d"
},
"spec/vectors/invalid/subject-with-an-unread-field.ccert": {
"norm": "1f231b88e2f8e786590e0fb8a89d0eeafc214d6c0af8e117a14a349ef35159c8",
"raw": "1f231b88e2f8e786590e0fb8a89d0eeafc214d6c0af8e117a14a349ef35159c8"
},
"spec/vectors/invalid/subject-with-an-unread-field.expect": {
"norm": "c03bc8fe5a0b97e2e9e8d67412f96c906f8a7e722801c91f71caf61b4b3e563e",
"raw": "c03bc8fe5a0b97e2e9e8d67412f96c906f8a7e722801c91f71caf61b4b3e563e"
},
"spec/vectors/invalid/subject-with-an-unread-field.why": {
"norm": "bd048b4e7b21a22a756e075518fb8076b875e4e250029e9ed7dc61d4062598ee",
"raw": "bd048b4e7b21a22a756e075518fb8076b875e4e250029e9ed7dc61d4062598ee"
},
"spec/vectors/invalid/trailing-bytes.ccert": {
"norm": "654fe86ca3d4ef57c59bba57cc8b12393bd7d0cb303937fece71150f04c90c25",
"raw": "654fe86ca3d4ef57c59bba57cc8b12393bd7d0cb303937fece71150f04c90c25"
},
"spec/vectors/invalid/trailing-bytes.expect": {
"norm": "fa69d7a9c4b0f5ac5b26fd00856f613febaae22857f7f337f3fc156a8360f858",
"raw": "fa69d7a9c4b0f5ac5b26fd00856f613febaae22857f7f337f3fc156a8360f858"
},
"spec/vectors/invalid/trailing-bytes.why": {
"norm": "ee27f30d9b2bb5f0fe97937cb9eedc2dfb1bcf601913835a3dbffe4a61dccfed",
"raw": "ee27f30d9b2bb5f0fe97937cb9eedc2dfb1bcf601913835a3dbffe4a61dccfed"
},
"spec/vectors/invalid/twist-class-at-the-wrong-degree.ccert": {
"norm": "6fd5f07bef21a78faf16e36148d3414ac69f09119648f348da9c9bbc15911987",
"raw": "6fd5f07bef21a78faf16e36148d3414ac69f09119648f348da9c9bbc15911987"
},
"spec/vectors/invalid/twist-class-at-the-wrong-degree.expect": {
"norm": "1eb41de617a5a6e1cdeef072edc31d7480c0ae80141fac9fe5a7cd0d199f480a",
"raw": "1eb41de617a5a6e1cdeef072edc31d7480c0ae80141fac9fe5a7cd0d199f480a"
},
"spec/vectors/invalid/twist-class-at-the-wrong-degree.why": {
"norm": "e64212ac336f732b7a2a1c3f9f5a5dc2ea572f0251c964a5a56067dd71ec0a7a",
"raw": "e64212ac336f732b7a2a1c3f9f5a5dc2ea572f0251c964a5a56067dd71ec0a7a"
},
"spec/vectors/invalid/twist-class-disagrees-with-evidence.ccert": {
"norm": "9551b3844a65199bff15719c8674d9de795a351903d36da73c7b6683e5191e85",
"raw": "9551b3844a65199bff15719c8674d9de795a351903d36da73c7b6683e5191e85"
},
"spec/vectors/invalid/twist-class-disagrees-with-evidence.expect": {
"norm": "56894a9239af78e2c1a7a2aa70b210c086ca67bece03d570ccb30fcfc6cdd09d",
"raw": "56894a9239af78e2c1a7a2aa70b210c086ca67bece03d570ccb30fcfc6cdd09d"
},
"spec/vectors/invalid/twist-class-disagrees-with-evidence.why": {
"norm": "aa1a09aa7b57c8054217ab86f4049554c0e0d69451238e9f5fc45fba853197fe",
"raw": "aa1a09aa7b57c8054217ab86f4049554c0e0d69451238e9f5fc45fba853197fe"
},
"spec/vectors/invalid/undeclared-dependency.ccert": {
"norm": "ab1982bfd9ed6a9e17fa641c973838e6acd9f0764bb69633500391472dd859ae",
"raw": "ab1982bfd9ed6a9e17fa641c973838e6acd9f0764bb69633500391472dd859ae"
},
"spec/vectors/invalid/undeclared-dependency.expect": {
"norm": "b71b01f35a9764d9a7febd4d5e532d2f175227ca1b58c98150f36c1d64d78bf1",
"raw": "b71b01f35a9764d9a7febd4d5e532d2f175227ca1b58c98150f36c1d64d78bf1"
},
"spec/vectors/invalid/undeclared-dependency.why": {
"norm": "982c2703dad20652171fd84b1ab810c811877b3217689efecb861bf84efad6ca",
"raw": "982c2703dad20652171fd84b1ab810c811877b3217689efecb861bf84efad6ca"
},
"spec/vectors/invalid/undersized-witness.ccert": {
"norm": "6f4656d2740921cf0a3e0ce2a338dd5d995cd4c4d312a454d21f9bd93032cfe2",
"raw": "6f4656d2740921cf0a3e0ce2a338dd5d995cd4c4d312a454d21f9bd93032cfe2"
},
"spec/vectors/invalid/undersized-witness.expect": {
"norm": "b856f239d102529f13fddd422e18e46644eba86bb0d90672cce8b67d572f575b",
"raw": "b856f239d102529f13fddd422e18e46644eba86bb0d90672cce8b67d572f575b"
},
"spec/vectors/invalid/undersized-witness.why": {
"norm": "a091a4957de8bf8f80d55fec27285441a01967243a8c482a5b44fded89b27e64",
"raw": "a091a4957de8bf8f80d55fec27285441a01967243a8c482a5b44fded89b27e64"
},
"spec/vectors/invalid/unexpected-byte.ccert": {
"norm": "4a60025ed58eceba483a89d53b60f4dbfd53df4e44b6e3b6769820a41ed0514d",
"raw": "4a60025ed58eceba483a89d53b60f4dbfd53df4e44b6e3b6769820a41ed0514d"
},
"spec/vectors/invalid/unexpected-byte.expect": {
"norm": "699a139e3958f54aab931c00ac785310b2399af2c47daee90b005f536efb6fa0",
"raw": "699a139e3958f54aab931c00ac785310b2399af2c47daee90b005f536efb6fa0"
},
"spec/vectors/invalid/unexpected-byte.why": {
"norm": "00fed3cbf7bb625dbbe3126b0557e52653bbeadb41e3cde6a75c6784ba1c01d9",
"raw": "00fed3cbf7bb625dbbe3126b0557e52653bbeadb41e3cde6a75c6784ba1c01d9"
},
"spec/vectors/invalid/unfactored-cofactor-with-a-claim.ccert": {
"norm": "4fc185ac4ef586f13f24fa21351230c698f998f780b3c4cb70993032347da8b6",
"raw": "4fc185ac4ef586f13f24fa21351230c698f998f780b3c4cb70993032347da8b6"
},
"spec/vectors/invalid/unfactored-cofactor-with-a-claim.expect": {
"norm": "5f0c62072418c199a01606568e8d475eb725fc77c13ac22956703813ea0df144",
"raw": "5f0c62072418c199a01606568e8d475eb725fc77c13ac22956703813ea0df144"
},
"spec/vectors/invalid/unfactored-cofactor-with-a-claim.why": {
"norm": "7b28d1264168a86d2a8390390a9d6ed449c9312d76bb77402054f1bfa5489637",
"raw": "7b28d1264168a86d2a8390390a9d6ed449c9312d76bb77402054f1bfa5489637"
},
"spec/vectors/invalid/unknown-escape.ccert": {
"norm": "6462fb82bd7db469313fc3a5749e339273473eea08176e99ac307e1a3082a4c7",
"raw": "6462fb82bd7db469313fc3a5749e339273473eea08176e99ac307e1a3082a4c7"
},
"spec/vectors/invalid/unknown-escape.expect": {
"norm": "52c30870ddafa36891abf873050ea3cb3205dd4f92907a09390fb48789120ddf",
"raw": "52c30870ddafa36891abf873050ea3cb3205dd4f92907a09390fb48789120ddf"
},
"spec/vectors/invalid/unknown-escape.why": {
"norm": "15b2ec20fecd53f847f1601fed64fc4aab7704fdc3fe1c41cd411614895c6399",
"raw": "15b2ec20fecd53f847f1601fed64fc4aab7704fdc3fe1c41cd411614895c6399"
},
"spec/vectors/invalid/unknown-family.ccert": {
"norm": "c5b382318ec50e80f10b1620bb6c137c0c04d7c07022b3a2be167fe96512aa9f",
"raw": "c5b382318ec50e80f10b1620bb6c137c0c04d7c07022b3a2be167fe96512aa9f"
},
"spec/vectors/invalid/unknown-family.expect": {
"norm": "33c3644d6b3f0a7abe4bde039b3c62fd4fb70e08c453f1294273d394a3b6d95e",
"raw": "33c3644d6b3f0a7abe4bde039b3c62fd4fb70e08c453f1294273d394a3b6d95e"
},
"spec/vectors/invalid/unknown-family.why": {
"norm": "a68792ff8670a71c4f0fe5f9c987b28ec475d031701136e243f42d16d19cd9de",
"raw": "a68792ff8670a71c4f0fe5f9c987b28ec475d031701136e243f42d16d19cd9de"
},
"spec/vectors/invalid/unknown-model.ccert": {
"norm": "0e932b75ede2f9623ed7cc4d7f560564012601c83e1ff6d989a76106c833af47",
"raw": "0e932b75ede2f9623ed7cc4d7f560564012601c83e1ff6d989a76106c833af47"
},
"spec/vectors/invalid/unknown-model.expect": {
"norm": "12b36ee600dbc6c93610fecd4a3f7f09aebe8c1be665efc9868f0ce49e2f4b9d",
"raw": "12b36ee600dbc6c93610fecd4a3f7f09aebe8c1be665efc9868f0ce49e2f4b9d"
},
"spec/vectors/invalid/unknown-model.why": {
"norm": "6a89caf8f9a81d945702060b81b7280fdf5a9d51f196a26f5dffe9c5ff209f15",
"raw": "6a89caf8f9a81d945702060b81b7280fdf5a9d51f196a26f5dffe9c5ff209f15"
},
"spec/vectors/invalid/unproved-characteristic.ccert": {
"norm": "10a39ee43dfa62a1341348a3d080215cb6dd207e13eb55f8e59d7ca3bedbca19",
"raw": "10a39ee43dfa62a1341348a3d080215cb6dd207e13eb55f8e59d7ca3bedbca19"
},
"spec/vectors/invalid/unproved-characteristic.expect": {
"norm": "1e81270f1a47dce22a2e4985250c74b2e3374443734f1492b03ea2cd2af4ec48",
"raw": "1e81270f1a47dce22a2e4985250c74b2e3374443734f1492b03ea2cd2af4ec48"
},
"spec/vectors/invalid/unproved-characteristic.why": {
"norm": "f1d6163a75c96351e675c5c3007a6cf5636f357939c0f2e2a2c5c2cfd2fb3513",
"raw": "f1d6163a75c96351e675c5c3007a6cf5636f357939c0f2e2a2c5c2cfd2fb3513"
},
"spec/vectors/invalid/unreduced-coordinate.ccert": {
"norm": "65a60d76da7f7b4fa4a39a8acc798c4fa29ebcdb637f3cd20410991db66bfc47",
"raw": "65a60d76da7f7b4fa4a39a8acc798c4fa29ebcdb637f3cd20410991db66bfc47"
},
"spec/vectors/invalid/unreduced-coordinate.expect": {
"norm": "808a46dc31e1402c78352bf57de51fa617c4f7f8d76a0dc8272a8624464d4a40",
"raw": "808a46dc31e1402c78352bf57de51fa617c4f7f8d76a0dc8272a8624464d4a40"
},
"spec/vectors/invalid/unreduced-coordinate.why": {
"norm": "18d3ddaa47a7db31f6131d9853934e32e99cda1ac93f8f873924d2f2835c20ad",
"raw": "18d3ddaa47a7db31f6131d9853934e32e99cda1ac93f8f873924d2f2835c20ad"
},
"spec/vectors/invalid/unsupported-twist-factor.ccert": {
"norm": "d47aff102bda364f61ef00b9ae0d2b746bdbba1373e49f9094b6d24739e16919",
"raw": "d47aff102bda364f61ef00b9ae0d2b746bdbba1373e49f9094b6d24739e16919"
},
"spec/vectors/invalid/unsupported-twist-factor.expect": {
"norm": "4fc88fdd42fff63d5ce763a7407dc567ba1eae3add059912acc900c8f8c79b2d",
"raw": "4fc88fdd42fff63d5ce763a7407dc567ba1eae3add059912acc900c8f8c79b2d"
},
"spec/vectors/invalid/unsupported-twist-factor.why": {
"norm": "7e76a4d84bb7c446b4b10582424153f0ec7927297031881a18761deeacca7482",
"raw": "7e76a4d84bb7c446b4b10582424153f0ec7927297031881a18761deeacca7482"
},
"spec/vectors/invalid/whitespace-in-key.ccert": {
"norm": "fd3138cb44d7be9893bf257d5eaf23aa0040a2ffc783e6e43f6c3f0e13eae478",
"raw": "fd3138cb44d7be9893bf257d5eaf23aa0040a2ffc783e6e43f6c3f0e13eae478"
},
"spec/vectors/invalid/whitespace-in-key.expect": {
"norm": "8e59a7b87e519ffa66aae938055e868f9834e793594391e696d1194f4e473d6a",
"raw": "8e59a7b87e519ffa66aae938055e868f9834e793594391e696d1194f4e473d6a"
},
"spec/vectors/invalid/whitespace-in-key.why": {
"norm": "03b8546942a831f465627af32d1c9663e11c122cee9953ad7d3bddcbdfb03795",
"raw": "03b8546942a831f465627af32d1c9663e11c122cee9953ad7d3bddcbdfb03795"
},
"spec/vectors/invalid/whitespace.ccert": {
"norm": "a9ce1de0e8666d4e39dd075a6e6de1acb388e955418ff10b5ea507a0ba4af936",
"raw": "a9ce1de0e8666d4e39dd075a6e6de1acb388e955418ff10b5ea507a0ba4af936"
},
"spec/vectors/invalid/whitespace.expect": {
"norm": "8048462be480547e068f6dc1bcf1cea815661281d080371fb7585a555faed5ea",
"raw": "8048462be480547e068f6dc1bcf1cea815661281d080371fb7585a555faed5ea"
},
"spec/vectors/invalid/whitespace.why": {
"norm": "d7b4abdff12e62ac47aae7d1e3946e4532360461226d64f386ac7619ca709f35",
"raw": "d7b4abdff12e62ac47aae7d1e3946e4532360461226d64f386ac7619ca709f35"
},
"spec/vectors/invalid/witness-point-with-an-unread-field.ccert": {
"norm": "34af7d57951234e83a5c6d38a7aa4ae5b2b6f2267d41f2d6748b593ee1b64b09",
"raw": "34af7d57951234e83a5c6d38a7aa4ae5b2b6f2267d41f2d6748b593ee1b64b09"
},
"spec/vectors/invalid/witness-point-with-an-unread-field.expect": {
"norm": "ffd4dade9b2fdac2561549e971f35c427b96863be93b831184f94bed6b97601a",
"raw": "ffd4dade9b2fdac2561549e971f35c427b96863be93b831184f94bed6b97601a"
},
"spec/vectors/invalid/witness-point-with-an-unread-field.why": {
"norm": "cc73901d83928f423a926170adcf3f6072a0aa20fd961eaf442da56d171fe679",
"raw": "cc73901d83928f423a926170adcf3f6072a0aa20fd961eaf442da56d171fe679"
},
"spec/vectors/invalid/wrong-cm-trace.ccert": {
"norm": "e1d93987acd8ad7ab336bcebe56eb4fc0eda62c85c84db6b5f8f46b018f08eef",
"raw": "e1d93987acd8ad7ab336bcebe56eb4fc0eda62c85c84db6b5f8f46b018f08eef"
},
"spec/vectors/invalid/wrong-cm-trace.expect": {
"norm": "ea4f8e5663bf24ef621b5f3bfe0f251e1f9d63d25cfdab35a3ff33ac277d8cc6",
"raw": "ea4f8e5663bf24ef621b5f3bfe0f251e1f9d63d25cfdab35a3ff33ac277d8cc6"
},
"spec/vectors/invalid/wrong-cm-trace.why": {
"norm": "24626342ad9b531084a633583785c71b2dc7eee3a8901009085b79801e086c1d",
"raw": "24626342ad9b531084a633583785c71b2dc7eee3a8901009085b79801e086c1d"
},
"spec/vectors/invalid/wrong-degree.ccert": {
"norm": "6f014afa8a14d35d457920a3e6542e03a761307636fe00f506ff2f0823d18e38",
"raw": "6f014afa8a14d35d457920a3e6542e03a761307636fe00f506ff2f0823d18e38"
},
"spec/vectors/invalid/wrong-degree.expect": {
"norm": "5e613784555c47a7e627801dc3fa742f1f132c543880d3b4d1bd23337c9d0fb4",
"raw": "5e613784555c47a7e627801dc3fa742f1f132c543880d3b4d1bd23337c9d0fb4"
},
"spec/vectors/invalid/wrong-degree.why": {
"norm": "d371369e31b677e5e949b0d0a6fe5660084850237e87c404642621185d806077",
"raw": "d371369e31b677e5e949b0d0a6fe5660084850237e87c404642621185d806077"
},
"spec/vectors/invalid/wrong-family-name.ccert": {
"norm": "0dc4535f100ee446e0f2219d19588031c22c8c675d129a4adcc00e19293c7030",
"raw": "0dc4535f100ee446e0f2219d19588031c22c8c675d129a4adcc00e19293c7030"
},
"spec/vectors/invalid/wrong-family-name.expect": {
"norm": "2b60b573591ce80b83dd20a57f293885d841b5379be8e645dfbcd48e8e358755",
"raw": "2b60b573591ce80b83dd20a57f293885d841b5379be8e645dfbcd48e8e358755"
},
"spec/vectors/invalid/wrong-family-name.why": {
"norm": "220ba447607c9888e44c4297df94953742b4eb64666718549b249def51795adc",
"raw": "220ba447607c9888e44c4297df94953742b4eb64666718549b249def51795adc"
},
"spec/vectors/invalid/wrong-family-parameter.ccert": {
"norm": "fffbc151c3acb33c764da3a49ebcb702749b42ecc6c7e3430a9054e5b9b49517",
"raw": "fffbc151c3acb33c764da3a49ebcb702749b42ecc6c7e3430a9054e5b9b49517"
},
"spec/vectors/invalid/wrong-family-parameter.expect": {
"norm": "f6f45e80007be85f7ee891728e6c09963c6c9dfd8fb62f4323760aeee64097ab",
"raw": "f6f45e80007be85f7ee891728e6c09963c6c9dfd8fb62f4323760aeee64097ab"
},
"spec/vectors/invalid/wrong-family-parameter.why": {
"norm": "3c6a6e19d176e05c2a6989272b6cb387e1d2ce5130f92082f809154afac85745",
"raw": "3c6a6e19d176e05c2a6989272b6cb387e1d2ce5130f92082f809154afac85745"
},
"spec/vectors/invalid/wrong-model-parameter.ccert": {
"norm": "72437ae357cf97b3d8cad93d7f3c027c41cf0a3e2d6ea363d67dacb6607b194c",
"raw": "72437ae357cf97b3d8cad93d7f3c027c41cf0a3e2d6ea363d67dacb6607b194c"
},
"spec/vectors/invalid/wrong-model-parameter.expect": {
"norm": "e8f9a7d69419d18c306be5d44876471ae3588e74d5403b7ddf0329e3fc32c5cd",
"raw": "e8f9a7d69419d18c306be5d44876471ae3588e74d5403b7ddf0329e3fc32c5cd"
},
"spec/vectors/invalid/wrong-model-parameter.why": {
"norm": "e7f61129c2bdd60d76a549cbdb6f45b64844e1b3834184ca4e1cdd9e5b14b7a3",
"raw": "e7f61129c2bdd60d76a549cbdb6f45b64844e1b3834184ca4e1cdd9e5b14b7a3"
},
"spec/vectors/invalid/wrong-twist-class.ccert": {
"norm": "45b84852c793e93e636f409f50a8b277769da232c858b1e66b8ac61490af738b",
"raw": "45b84852c793e93e636f409f50a8b277769da232c858b1e66b8ac61490af738b"
},
"spec/vectors/invalid/wrong-twist-class.expect": {
"norm": "b79ddf67c376df95a9d3e54f6195ecb9f567b0f82d9723bbbdf5aaf5f2c0f6bd",
"raw": "b79ddf67c376df95a9d3e54f6195ecb9f567b0f82d9723bbbdf5aaf5f2c0f6bd"
},
"spec/vectors/invalid/wrong-twist-class.why": {
"norm": "dbc02493189320770d8b47dec1068aff4f4a29193a8793b7375b5378e553e205",
"raw": "dbc02493189320770d8b47dec1068aff4f4a29193a8793b7375b5378e553e205"
},
"spec/vectors/invalid/wrong-twist-v.ccert": {
"norm": "841d730736ae23d876c391de93162ff2101025e2188bcf845ef0fc018482cbe5",
"raw": "841d730736ae23d876c391de93162ff2101025e2188bcf845ef0fc018482cbe5"
},
"spec/vectors/invalid/wrong-twist-v.expect": {
"norm": "926dbb5e0d4d25833171233d9c3dd9284b3cbfb43887da365d3007aad90aecc3",
"raw": "926dbb5e0d4d25833171233d9c3dd9284b3cbfb43887da365d3007aad90aecc3"
},
"spec/vectors/invalid/wrong-twist-v.why": {
"norm": "428cbb9f24ad6a90dbb625e17d7bd86a833462ae329d544f047a3e336870f206",
"raw": "428cbb9f24ad6a90dbb625e17d7bd86a833462ae329d544f047a3e336870f206"
},
"spec/vectors/valid/.gitkeep": {
"norm": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
"raw": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
},
"spec/vectors/valid/bls12-381.ccert": {
"norm": "86dc97414436e88191209b97862a999e3768cc838551f7262dad0f170e8b85b0",
"raw": "86dc97414436e88191209b97862a999e3768cc838551f7262dad0f170e8b85b0"
},
"spec/vectors/valid/bls24-315.ccert": {
"norm": "51958b98d63ddca4fff20fa9ee70b2897f0b687e6f8ebdd524a9de1a82a889ef",
"raw": "51958b98d63ddca4fff20fa9ee70b2897f0b687e6f8ebdd524a9de1a82a889ef"
},
"spec/vectors/valid/bls24-509.ccert": {
"norm": "9515dcf156964b8566f2f37d72d5d039488f2a5cd113c11bc5f8799b71cb0626",
"raw": "9515dcf156964b8566f2f37d72d5d039488f2a5cd113c11bc5f8799b71cb0626"
},
"spec/vectors/valid/bn254.ccert": {
"norm": "cd962b7ecf47972acd44b09b0d34f82dd85501c2e651403376f3f79378d455b5",
"raw": "cd962b7ecf47972acd44b09b0d34f82dd85501c2e651403376f3f79378d455b5"
},
"spec/vectors/valid/curve25519.ccert": {
"norm": "79180506fd6621ddb4d931568059b06fd8fd506067ea48861bf595523505f404",
"raw": "79180506fd6621ddb4d931568059b06fd8fd506067ea48861bf595523505f404"
},
"spec/vectors/valid/ed25519.ccert": {
"norm": "2e6f943853e4f68880b6fdc41cb6c55d222900f0a93bb44c027ca59235f91906",
"raw": "2e6f943853e4f68880b6fdc41cb6c55d222900f0a93bb44c027ca59235f91906"
},
"spec/vectors/valid/p-256.ccert": {
"norm": "8e578f6b44725467070e135b622969ca7e2871c749ccb60f1c5f33e2b5b7b7ad",
"raw": "8e578f6b44725467070e135b622969ca7e2871c749ccb60f1c5f33e2b5b7b7ad"
},
"spec/vectors/valid/secp256k1.ccert": {
"norm": "476a543834bdea6be9662e15ddc3a0ec27c8f70361fc3e69a67566a7213ea3b6",
"raw": "476a543834bdea6be9662e15ddc3a0ec27c8f70361fc3e69a67566a7213ea3b6"
},
"tests/__init__.py": {
"norm": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
"raw": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
},
"tests/test_build_curve.py": {
"norm": "6bb7335a70f0f1159ee6e9d4ab6f882e538bf85d354dd55cf8c75154c846174e",
"raw": "6bb7335a70f0f1159ee6e9d4ab6f882e538bf85d354dd55cf8c75154c846174e"
},
"tests/test_bundle.py": {
"norm": "e87c15a055e157e57e7254d6ec6a8570fb7b017e277104bff19fde415915c418",
"raw": "e87c15a055e157e57e7254d6ec6a8570fb7b017e277104bff19fde415915c418"
},
"tests/test_ccert_diff.py": {
"norm": "b87e758081941a9f1f55f3aa6815e04d53185e89db78495d3e200f645a602aa5",
"raw": "b87e758081941a9f1f55f3aa6815e04d53185e89db78495d3e200f645a602aa5"
},
"tests/test_explain.py": {
"norm": "c39162527886ea3283ad5cdc80fae9a7d60bd31068fb14c0f584d987d4485453",
"raw": "c39162527886ea3283ad5cdc80fae9a7d60bd31068fb14c0f584d987d4485453"
},
"tests/test_family.py": {
"norm": "5f0156cb4738111f55a5c8ded409c7c85c2fdb84c0348c97cac99a1e3887e708",
"raw": "5f0156cb4738111f55a5c8ded409c7c85c2fdb84c0348c97cac99a1e3887e708"
},
"tests/test_field_laws.py": {
"norm": "7d74b72b7f6e65e98d0f960c23dab1b7f98a159c577713eebb59a1cea42f4505",
"raw": "7d74b72b7f6e65e98d0f960c23dab1b7f98a159c577713eebb59a1cea42f4505"
},
"tests/test_fp.py": {
"norm": "d9962236fd88467cafb652e1bd3dcfcf97eaf7455b95ef618fcb65fb8968fbea",
"raw": "d9962236fd88467cafb652e1bd3dcfcf97eaf7455b95ef618fcb65fb8968fbea"
},
"tests/test_fp2.py": {
"norm": "cae42907d73a7c3811f5108eae0f47478c39661b48b90839df7a43b294192be2",
"raw": "cae42907d73a7c3811f5108eae0f47478c39661b48b90839df7a43b294192be2"
},
"tests/test_fp4.py": {
"norm": "9fdaca35edecf83e4f669ba8f44179340755480723757e57f2852af42920f94b",
"raw": "9fdaca35edecf83e4f669ba8f44179340755480723757e57f2852af42920f94b"
},
"tests/test_gp_backend.py": {
"norm": "3372876d661eacdb298f8dc2d508a48f4d54c9273c12058a610ba741a7e12929",
"raw": "3372876d661eacdb298f8dc2d508a48f4d54c9273c12058a610ba741a7e12929"
},
"tests/test_gp_fp2.py": {
"norm": "325565af9e2325751485b394c700b3c65d4e4a04ea11169c80e089decb8f24a3",
"raw": "325565af9e2325751485b394c700b3c65d4e4a04ea11169c80e089decb8f24a3"
},
"tests/test_invalid_vectors.py": {
"norm": "490435ed849ae20eb01236928ae9d65e7337611542e65d623d58f46a49a4e46f",
"raw": "490435ed849ae20eb01236928ae9d65e7337611542e65d623d58f46a49a4e46f"
},
"tests/test_json_output.py": {
"norm": "71109bef0559547855a51d0010d6a1822d22512a04beb867a0a983a428e33c4a",
"raw": "71109bef0559547855a51d0010d6a1822d22512a04beb867a0a983a428e33c4a"
},
"tests/test_layout.py": {
"norm": "1da334993305e4b8d50810314f5d0ca3018724174a1b30707d5d228a0467e14d",
"raw": "1da334993305e4b8d50810314f5d0ca3018724174a1b30707d5d228a0467e14d"
},
"tests/test_models.py": {
"norm": "4db1b603312116cdf68c3166e76428aa68117e1125b28d21e648f6cc16619046",
"raw": "4db1b603312116cdf68c3166e76428aa68117e1125b28d21e648f6cc16619046"
},
"tests/test_pairing.py": {
"norm": "aa357d0ee587acc9aa467f8002ccc72d6aed7ba4453ecc59b8d16cd6a8beb97f",
"raw": "aa357d0ee587acc9aa467f8002ccc72d6aed7ba4453ecc59b8d16cd6a8beb97f"
},
"tests/test_pairing_policy.py": {
"norm": "ee4f703558168964e8d2bd03f71f4edc7a22e32d4b5aab6c6043b4c5ef44b64b",
"raw": "ee4f703558168964e8d2bd03f71f4edc7a22e32d4b5aab6c6043b4c5ef44b64b"
},
"tests/test_point_order.py": {
"norm": "d24538ea30ebc72a7a32e3a2388c65ed7d143ea5367f19521a09fd7085b77cd0",
"raw": "d24538ea30ebc72a7a32e3a2388c65ed7d143ea5367f19521a09fd7085b77cd0"
},
"tests/test_policy.py": {
"norm": "64ee477fcc3f4fe764e03cd3a37fb2b8938524f937cef4d8f5d845ef84fc9b5c",
"raw": "64ee477fcc3f4fe764e03cd3a37fb2b8938524f937cef4d8f5d845ef84fc9b5c"
},
"tests/test_policy_agreement.py": {
"norm": "4a90503a44fc2e2d6884cf2c8521f25591df97a90e51a01fa89df8e577cadf5c",
"raw": "4a90503a44fc2e2d6884cf2c8521f25591df97a90e51a01fa89df8e577cadf5c"
},
"tests/test_policy_mirror.py": {
"norm": "bcb39961fdf69fc56acaf2fe1f1d5b8dec698ec272cf9674efa20551bc2781d4",
"raw": "bcb39961fdf69fc56acaf2fe1f1d5b8dec698ec272cf9674efa20551bc2781d4"
},
"tests/test_release.py": {
"norm": "cd6667cb210236339a27514def413529a47b878598ed7a24833251e3a114a860",
"raw": "cd6667cb210236339a27514def413529a47b878598ed7a24833251e3a114a860"
},
"tests/test_snark.py": {
"norm": "d77e117918270cb0d0af23d0e54020def7b71304c4b929b47f583cdc50d11bea",
"raw": "d77e117918270cb0d0af23d0e54020def7b71304c4b929b47f583cdc50d11bea"
},
"tests/test_soundness.py": {
"norm": "d5a2207bde0b7753f32bb2fcd7d94d308eebb59ab933570e6e34056a9500979f",
"raw": "d5a2207bde0b7753f32bb2fcd7d94d308eebb59ab933570e6e34056a9500979f"
},
"tests/test_spec.py": {
"norm": "499c0b7947a7508ce1f2248193ebca00e55c420c7ce3634c9114760c3ea21efc",
"raw": "499c0b7947a7508ce1f2248193ebca00e55c420c7ce3634c9114760c3ea21efc"
},
"tests/test_twist.py": {
"norm": "7389fe1a813f71b25f649c8c4986c4660f4e1b666e28bc014c2313603c2a21fe",
"raw": "7389fe1a813f71b25f649c8c4986c4660f4e1b666e28bc014c2313603c2a21fe"
},
"tests/test_verifier.py": {
"norm": "aa10e87993a1326c249296e275f54aa3b6d0aa5e88408da0ec13e5cdfc52de0c",
"raw": "aa10e87993a1326c249296e275f54aa3b6d0aa5e88408da0ec13e5cdfc52de0c"
},
"tests/test_verifier_pairing.py": {
"norm": "fba1c7c797a3df4a8010ef8d020b926e8ee2b4eb4d77707786e409de03d5fe7f",
"raw": "fba1c7c797a3df4a8010ef8d020b926e8ee2b4eb4d77707786e409de03d5fe7f"
},
"tests/test_web_export.py": {
"norm": "f90304755f2638b18b44059700c86fb3d62e41925cab3a6430dafa08b85b3a8f",
"raw": "f90304755f2638b18b44059700c86fb3d62e41925cab3a6430dafa08b85b3a8f"
},
"tests/verify.bat": {
"norm": "8807869757dca7ad9809861170da0d9e0d87401a9d19345b67b39113a9165d02",
"raw": "8807869757dca7ad9809861170da0d9e0d87401a9d19345b67b39113a9165d02"
},
"tools/bench.py": {
"norm": "ad0185d62d1373fcd616d36f520206b849cc6d7e8d40f233a9f804773d571732",
"raw": "ad0185d62d1373fcd616d36f520206b849cc6d7e8d40f233a9f804773d571732"
},
"tools/build_curve.py": {
"norm": "fc0276f0fee1ffa0d62a913be7a69ddc0ebc974c693181d58ad277cfae3db8aa",
"raw": "fc0276f0fee1ffa0d62a913be7a69ddc0ebc974c693181d58ad277cfae3db8aa"
},
"tools/build_verifier.bat": {
"norm": "e58ae1fc44421bd303fe53aaacfca2194984831fe0b934e48fc21710e79576a0",
"raw": "54467ec562bc5b9037ec8416ad0102bdc1aaec6f70a765f8a2fdfa0cf3b79869"
},
"tools/build_wasm.bat": {
"norm": "e0d2572b930a7d4ad6b3ce2c3c0150c5d46f8e0aabe68bbd32f8135d5b1f0c69",
"raw": "e0d2572b930a7d4ad6b3ce2c3c0150c5d46f8e0aabe68bbd32f8135d5b1f0c69"
},
"tools/ccert_diff.py": {
"norm": "64feb506f9070f2b9fc2de9d087b049fd751773202d2eb4a08244c333e17071d",
"raw": "64feb506f9070f2b9fc2de9d087b049fd751773202d2eb4a08244c333e17071d"
},
"tools/ci_local.sh": {
"norm": "581903ce4f89cbcb51ec8b3bd2577b54764f420d4d3f9c53e6bb2f567319e524",
"raw": "581903ce4f89cbcb51ec8b3bd2577b54764f420d4d3f9c53e6bb2f567319e524"
},
"tools/corpus.bat": {
"norm": "e708e696b68c644f1fae6e8c86ffb7e7a0be404db4ad8d0ef6608671f1a8681d",
"raw": "7eba36be2d7e5a40ea61a481fcbc8b3e16a73efdbe770780e83cd36db4f67738"
},
"tools/dist.bat": {
"norm": "3d7615ea8d620cbbae6a9c8d815ff8e366aa3d9372475b8dc05abf4cade89875",
"raw": "3d7615ea8d620cbbae6a9c8d815ff8e366aa3d9372475b8dc05abf4cade89875"
},
"tools/env_check.py": {
"norm": "06ca59e09368ce1985d0916606e6efe7599435ed50b293bc2de072357c971fca",
"raw": "06ca59e09368ce1985d0916606e6efe7599435ed50b293bc2de072357c971fca"
},
"tools/export_web.py": {
"norm": "ed38eb490c8ec3d1c7237b2b63abe59ba36c433cfc7c0dba987695daec6bd690",
"raw": "ed38eb490c8ec3d1c7237b2b63abe59ba36c433cfc7c0dba987695daec6bd690"
},
"tools/gp_selftest.bat": {
"norm": "c01bca0ff1a91d175ab8dcd3f708f5dfae51462e741b6ebd0692bd9850d8c93d",
"raw": "c01bca0ff1a91d175ab8dcd3f708f5dfae51462e741b6ebd0692bd9850d8c93d"
},
"tools/inline_wasm.py": {
"norm": "8d54d1f7a49dad061af60fb097f0b9ac9ac345780beabfb2a919c1adaad4cbef",
"raw": "8d54d1f7a49dad061af60fb097f0b9ac9ac345780beabfb2a919c1adaad4cbef"
},
"tools/make_cert.bat": {
"norm": "f77d7e7350acf15e7f7ee56372ddba38b7199d0451b4ec3a10e905e66ffcbfd3",
"raw": "f77d7e7350acf15e7f7ee56372ddba38b7199d0451b4ec3a10e905e66ffcbfd3"
},
"tools/make_invalid_vectors.py": {
"norm": "ff7fb35b25622349155c3f97ba3a48d42051a6c5780b580611293d6cdd890bbb",
"raw": "ff7fb35b25622349155c3f97ba3a48d42051a6c5780b580611293d6cdd890bbb"
},
"tools/make_release.py": {
"norm": "a21f9561270b549027e951fe32e4f86aa3db414a382f4f7c81879984d75e191a",
"raw": "a21f9561270b549027e951fe32e4f86aa3db414a382f4f7c81879984d75e191a"
},
"tools/policy.bat": {
"norm": "3206477e666ba091b64a3a61ebf4a63f587f2b8730f107f8c95c4f5e685e796f",
"raw": "3206477e666ba091b64a3a61ebf4a63f587f2b8730f107f8c95c4f5e685e796f"
},
"tools/repo.bat": {
"norm": "04831051831eac793f89a4c7868fb98db4297b3965f04d709e4736e74e5b8aa6",
"raw": "04831051831eac793f89a4c7868fb98db4297b3965f04d709e4736e74e5b8aa6"
},
"tools/stage_repo.py": {
"norm": "335c5b9926e02becbe1af83613aa9a76ba8d6582c5295bfeccb6ce2363d8b75d",
"raw": "335c5b9926e02becbe1af83613aa9a76ba8d6582c5295bfeccb6ce2363d8b75d"
},
"tools/test.bat": {
"norm": "9d627615d36be3924de4936434d395de3b4d95dbe8036197471f1f63354347eb",
"raw": "9d627615d36be3924de4936434d395de3b4d95dbe8036197471f1f63354347eb"
},
"tools/test_gp_backend.py": {
"norm": "3372876d661eacdb298f8dc2d508a48f4d54c9273c12058a610ba741a7e12929",
"raw": "3372876d661eacdb298f8dc2d508a48f4d54c9273c12058a610ba741a7e12929"
},
"tools/test_web_export.py": {
"norm": "baa88680bd06df5f6b8dad344638093fc475a1fc54fb07bce127e5b95768ba07",
"raw": "baa88680bd06df5f6b8dad344638093fc475a1fc54fb07bce127e5b95768ba07"
},
"tools/verify.bat": {
"norm": "603e69f60629fabc1d3068608d3b866dd1f23abd4fbc185c80de94507b5bc174",
"raw": "603e69f60629fabc1d3068608d3b866dd1f23abd4fbc185c80de94507b5bc174"
},
"tools/wasm_stamp.py": {
"norm": "169e86e4eab1fc8360e9cd0a228900ad8b78623fb63297d659151767ece1f591",
"raw": "169e86e4eab1fc8360e9cd0a228900ad8b78623fb63297d659151767ece1f591"
},
"tools/web.bat": {
"norm": "3623ce9c2f08a38d6abd54851f687655371fb46f1c53d0974a664c4d5144d9a6",
"raw": "3623ce9c2f08a38d6abd54851f687655371fb46f1c53d0974a664c4d5144d9a6"
},
"tools/web_build.bat": {
"norm": "f86fd53819f6320bb122e129a26cef8ab3508541453731e487031d378f1e3f43",
"raw": "157a248de52ca566b7bbecfd8a23146b9f22c13d550b3793f71bc2ccdec86d89"
},
"tools/web_data.bat": {
"norm": "12ec1baa97b038f9f8a70a5017e4e5ed1393d21f62a265586e589370875e936b",
"raw": "12ec1baa97b038f9f8a70a5017e4e5ed1393d21f62a265586e589370875e936b"
},
"verifier/Cargo.lock": {
"norm": "54b7b314446cdd8c0087f1a3ddeca496349a1edb73bd9de8219b1da7c26b1da3",
"raw": "54b7b314446cdd8c0087f1a3ddeca496349a1edb73bd9de8219b1da7c26b1da3"
},
"verifier/Cargo.toml": {
"norm": "9138aa64de6cc67e6e95c0c2736092edfb734a82aed87eead1e8c64ff9b5fc60",
"raw": "9138aa64de6cc67e6e95c0c2736092edfb734a82aed87eead1e8c64ff9b5fc60"
},
"verifier/README.md": {
"norm": "0e991f94495a82067da745b38d9aa2ddadcffab8763ad8db40998aa3cbeda5cc",
"raw": "0e991f94495a82067da745b38d9aa2ddadcffab8763ad8db40998aa3cbeda5cc"
},
"verifier/fuzz/Cargo.toml": {
"norm": "6da6e9beed5f5d0c3fb01b7d4c9be1b4092d9ecc9e7e2b9c9684a419313dc096",
"raw": "6da6e9beed5f5d0c3fb01b7d4c9be1b4092d9ecc9e7e2b9c9684a419313dc096"
},
"verifier/fuzz/fuzz_targets/parse.rs": {
"norm": "867d6324672df1281a192c5175d1c6274fa0f9d145c89e82f629c5315f929bad",
"raw": "867d6324672df1281a192c5175d1c6274fa0f9d145c89e82f629c5315f929bad"
},
"verifier/fuzz/fuzz_targets/verify_text.rs": {
"norm": "bb9809e9de26fa49e3715ccb49f0ff8fa4d9dbfd29c45d872b50a6e289180833",
"raw": "bb9809e9de26fa49e3715ccb49f0ff8fa4d9dbfd29c45d872b50a6e289180833"
},
"verifier/src/claims.rs": {
"norm": "4accb180843f4a50532a8f9d20d1300aaad87fb75aef2d4162c2d448c61d1e23",
"raw": "4accb180843f4a50532a8f9d20d1300aaad87fb75aef2d4162c2d448c61d1e23"
},
"verifier/src/curve.rs": {
"norm": "514df81c4eaf20a8571b20d3519b9179a11daed60d6ef0451bba436d05259169",
"raw": "514df81c4eaf20a8571b20d3519b9179a11daed60d6ef0451bba436d05259169"
},
"verifier/src/curve_model.rs": {
"norm": "6b6ed10a06857e6b2246c29a5ae9ba899e6b2e2e6bb24ca66370c3886b12f173",
"raw": "6b6ed10a06857e6b2246c29a5ae9ba899e6b2e2e6bb24ca66370c3886b12f173"
},
"verifier/src/ec.rs": {
"norm": "fd7d6e6960cfdd66e2fb74d61121f0c174306cf5b54cfbd843c698df9400785a",
"raw": "fd7d6e6960cfdd66e2fb74d61121f0c174306cf5b54cfbd843c698df9400785a"
},
"verifier/src/ecpp.rs": {
"norm": "ff9267cd7b24c49ac6678c9ca14ad9d8b83f630ee56a2d4435129a3ad85089a7",
"raw": "ff9267cd7b24c49ac6678c9ca14ad9d8b83f630ee56a2d4435129a3ad85089a7"
},
"verifier/src/elimination.rs": {
"norm": "67742dd52c3558c73e3d60ebb6ecb98bb8467e6aad72d3a15d0eac67a026bebd",
"raw": "67742dd52c3558c73e3d60ebb6ecb98bb8467e6aad72d3a15d0eac67a026bebd"
},
"verifier/src/family.rs": {
"norm": "2cbc132f90d533fc342e2bc4c99aef0c5123da4b6f40219126955c10675397b2",
"raw": "2cbc132f90d533fc342e2bc4c99aef0c5123da4b6f40219126955c10675397b2"
},
"verifier/src/fq.rs": {
"norm": "f592910741502f420b21581a230c0ef08707a4e4b06f10bb0e443b6db6d4601d",
"raw": "f592910741502f420b21581a230c0ef08707a4e4b06f10bb0e443b6db6d4601d"
},
"verifier/src/fq4.rs": {
"norm": "a33f60fdec9c87c799fc9947e68114a65d1573609e613f5ef13536e7f7625cd7",
"raw": "a33f60fdec9c87c799fc9947e68114a65d1573609e613f5ef13536e7f7625cd7"
},
"verifier/src/fuzz_oracle.rs": {
"norm": "9b9f75b3e676dbf438ce3b5a3ce33c3844c612b227139b13ae6fa305546fecbb",
"raw": "9b9f75b3e676dbf438ce3b5a3ce33c3844c612b227139b13ae6fa305546fecbb"
},
"verifier/src/json.rs": {
"norm": "74f153d8d0e6d5d1a03dbd43b5983e1479a3711e9cb9be7fb518a1d2343e57c5",
"raw": "74f153d8d0e6d5d1a03dbd43b5983e1479a3711e9cb9be7fb518a1d2343e57c5"
},
"verifier/src/lib.rs": {
"norm": "794a44672539cc0060356455e993155448f4aff9e3577b98061ba9b4ea8767ba",
"raw": "794a44672539cc0060356455e993155448f4aff9e3577b98061ba9b4ea8767ba"
},
"verifier/src/main.rs": {
"norm": "25487dfd3f1bd483ad448fb05a4809a4faf223304c49bc960487ea3c92c86dfa",
"raw": "25487dfd3f1bd483ad448fb05a4809a4faf223304c49bc960487ea3c92c86dfa"
},
"verifier/src/point_order.rs": {
"norm": "9c29a38455d133e73978c645e351f24d363b78538d3954dacfb414cc7fc1e2e8",
"raw": "9c29a38455d133e73978c645e351f24d363b78538d3954dacfb414cc7fc1e2e8"
},
"verifier/src/twist_class.rs": {
"norm": "e60a120a36ecde24a90b597c4390ae4384532225dbadc7777229123555d74f6b",
"raw": "e60a120a36ecde24a90b597c4390ae4384532225dbadc7777229123555d74f6b"
},
"verifier/src/verify.rs": {
"norm": "0ffbb001ea52e446128fc90169b954e2dfc54597fca5b7cd223158e7c9fc1d76",
"raw": "0ffbb001ea52e446128fc90169b954e2dfc54597fca5b7cd223158e7c9fc1d76"
},
"verifier/tests/.gitkeep": {
"norm": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
"raw": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
},
"verifier/tests/fuzz_oracle.rs": {
"norm": "30f4606b0161fdcab3c61d142e6bad481139d71d2269fa5f7282292b174b392a",
"raw": "30f4606b0161fdcab3c61d142e6bad481139d71d2269fa5f7282292b174b392a"
},
"verifier/tests/proptest_laws.rs": {
"norm": "e6c0095cff6e053f6b82bc74942c87be72cae960e70ecb2694e6d66a552d1414",
"raw": "e6c0095cff6e053f6b82bc74942c87be72cae960e70ecb2694e6d66a552d1414"
},
"web/.gitignore": {
"norm": "fe718e7babb14f3cbad2d97f08889b9ce5215ed3fe0e43b2b8cfbfb3b9b844e8",
"raw": "fe718e7babb14f3cbad2d97f08889b9ce5215ed3fe0e43b2b8cfbfb3b9b844e8"
},
"web/.oxlintrc.json": {
"norm": "1be899e45c49b2a2edc715bc3bfb31d8ed8e866ed7ebab2065ff6e55e88c2396",
"raw": "1be899e45c49b2a2edc715bc3bfb31d8ed8e866ed7ebab2065ff6e55e88c2396"
},
"web/README.md": {
"norm": "1f8fa46483b514305f44e34a47e85e88428c3a667c9494e1583628ef18d7bc79",
"raw": "1f8fa46483b514305f44e34a47e85e88428c3a667c9494e1583628ef18d7bc79"
},
"web/index.css": {
"norm": "30f0af75ce652c3d0ad88e6daf0dc2c02a64ae9df55b3ff2817febb902281ec2",
"raw": "30f0af75ce652c3d0ad88e6daf0dc2c02a64ae9df55b3ff2817febb902281ec2"
},
"web/index.html": {
"norm": "811ca821d62ba5dc0146e8fea5178e114ef845ed9a16e8e1af47a788e3741a9e",
"raw": "811ca821d62ba5dc0146e8fea5178e114ef845ed9a16e8e1af47a788e3741a9e"
},
"web/package-lock.json": {
"norm": "4a059091b45bdd8ee967470f62a458ebad2f3ce4e4dab9907a593bc78667f881",
"raw": "4a059091b45bdd8ee967470f62a458ebad2f3ce4e4dab9907a593bc78667f881"
},
"web/package.json": {
"norm": "99230e398bf1703385ae0f39c5659b2ed7b2273e8bb64f6c9b9c564e727a10eb",
"raw": "99230e398bf1703385ae0f39c5659b2ed7b2273e8bb64f6c9b9c564e727a10eb"
},
"web/public/favicon.svg": {
"norm": "61bc9a161de58248288e6905425d7180f0624c2865007b97d763fdac12043a66",
"raw": "61bc9a161de58248288e6905425d7180f0624c2865007b97d763fdac12043a66"
},
"web/public/icons.svg": {
"norm": "b45fa506195cfcdef406ba9f0c77b36ddc1a7c224040926ec70abc2fdea7b93a",
"raw": "b45fa506195cfcdef406ba9f0c77b36ddc1a7c224040926ec70abc2fdea7b93a"
},
"web/src/App.jsx": {
"norm": "052cc231b021956e3a9425139f89c97443ddb059b51971ebe28d3ddef9239ecf",
"raw": "052cc231b021956e3a9425139f89c97443ddb059b51971ebe28d3ddef9239ecf"
},
"web/src/assets/hero.png": {
"norm": "cfdde5b97f7abbdde251933fda164ea3d0d920a219bf2f8c48c1e22cbf3acfe0",
"raw": "881ffbcaafc212e49addad08846a5b82761355fa20624253af3477ba33262c5c"
},
"web/src/assets/react.svg": {
"norm": "35ef61ed53b323ae94a16a8ec659b3d0af3880698791133f23b084085ab1c2e5",
"raw": "35ef61ed53b323ae94a16a8ec659b3d0af3880698791133f23b084085ab1c2e5"
},
"web/src/assets/vite.svg": {
"norm": "5be21acd42eb7b896e517f4e0f0f11eb5c5d9e54fbbcebe9453f033008fcca6f",
"raw": "5be21acd42eb7b896e517f4e0f0f11eb5c5d9e54fbbcebe9453f033008fcca6f"
},
"web/src/index.css": {
"norm": "074244b34372d905aeed7e3e4722cae5b8be5f28e7f4dbb1de9236462e33c74b",
"raw": "074244b34372d905aeed7e3e4722cae5b8be5f28e7f4dbb1de9236462e33c74b"
},
"web/src/index.html": {
"norm": "0f7fa40e049c9e4c9fd4e864ce825e8d3866533d06a2bd5954774f496b9139ba",
"raw": "0f7fa40e049c9e4c9fd4e864ce825e8d3866533d06a2bd5954774f496b9139ba"
},
"web/src/main.jsx": {
"norm": "70b0f7e347ec5cbabb5c9cc42f3e1a1366be1d10d001570fd9913fcd0bf687eb",
"raw": "70b0f7e347ec5cbabb5c9cc42f3e1a1366be1d10d001570fd9913fcd0bf687eb"
},
"web/src/policy.js": {
"norm": "5c589815ed4d0f80a962db57ce9155dd34ea9d2c12e526e392268fcdbf07a430",
"raw": "5c589815ed4d0f80a962db57ce9155dd34ea9d2c12e526e392268fcdbf07a430"
},
"web/src/verifier.placeholder.js": {
"norm": "dba37e7290542edc45c110c9762026d72289a889239e786ea7cf7b9511f162ed",
"raw": "dba37e7290542edc45c110c9762026d72289a889239e786ea7cf7b9511f162ed"
},
"web/src/wasm/ccert.js": {
"norm": "a887528c4660736edd152132b9988be55eb8b232cf2e9cad3c386cb84fd09ad6",
"raw": "a887528c4660736edd152132b9988be55eb8b232cf2e9cad3c386cb84fd09ad6"
},
"web/src/wasm/ccert_bg.wasm": {
"norm": "aab1c28f41450881413834f2b82839b2ee3b7cecdc4c23d7db2f8cb5bc4da4c0",
"raw": "78ab453b82e673f90100ad5d3e9affd644385de31615fefa504d46e1a4530951"
},
"web/vite.config.js": {
"norm": "2a6c49e04bb03b211ff47c6e4db951db8cdd1c64dc2d6a1400f0b8a32507c670",
"raw": "2a6c49e04bb03b211ff47c6e4db951db8cdd1c64dc2d6a1400f0b8a32507c670"
},
}


def _hashes(data: bytes) -> tuple:
    raw = hashlib.sha256(data).hexdigest()
    norm = hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
    return raw, norm


def main() -> int:
    root = pathlib.Path(".")
    if not (root / "verifier" / "src").is_dir():
        print("run this from the E:\\EK project root", file=sys.stderr)
        return 2

    present = {}
    for rel in tracked_paths(root):
        try:
            data = (root / rel).read_bytes()
        except FileNotFoundError:
            # Tracked but deleted in the working tree; surfaces as MISSING
            # below if the manifest expected it.
            continue
        present[rel] = _hashes(data)

    damaged, eol_only, missing, extra = [], [], [], []
    for rel, ref in REFERENCE.items():
        if rel not in present:
            missing.append(rel)
            continue
        raw, norm = present[rel]
        if raw == ref["raw"]:
            continue
        if norm == ref["norm"]:
            eol_only.append(rel)
        else:
            damaged.append(rel)
    for rel in present:
        if rel not in REFERENCE:
            extra.append(rel)

    for label, items in (("DAMAGED", damaged), ("MISSING", missing),
                         ("EXTRA", extra), ("EOL-ONLY", eol_only)):
        if items:
            print(f"\n=== {label} ({len(items)}) ===")
            for k in sorted(items):
                print(f"  {k}")

    print()
    if not (damaged or missing or extra or eol_only):
        print("clean: every tracked file matches the manifest, byte for byte")
        return 0
    if not (damaged or missing or extra):
        print(f"content is intact: {len(eol_only)} file(s) differ only in line")
        print("endings (CRLF vs LF). Harmless for reading, but a .ccert in CRLF")
        print("has a different digest — .gitattributes pins LF to stop this.")
        return 0
    print(f"summary: {len(damaged)} damaged, {len(missing)} missing, "
          f"{len(extra)} extra, {len(eol_only)} eol-only")
    print("\nDAMAGED, MISSING and EXTRA are real; EOL-ONLY is newline noise.")
    print("Send this output back.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
