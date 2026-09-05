# anonctl brand assets

## The mark, in two sentences

An `@` sigil: the ring is the account's boundary, the rounded-square `a` inside it is the UID living in that boundary, and the `a`'s stem descends, turns accent green, and leaves through the ring's one opening. That green path is the account's forced egress: it is the only way out, and it exists at exactly one place in an otherwise closed enclosure.

The `@` is not decoration borrowed from email. anonctl dials a shared Tor endpoint with a per-account SOCKS username (`<account>@`), which is what Tor's `IsolateSOCKSAuth` keys a distinct circuit and exit on, so identity-at-host is literally the mechanism. The mark deliberately draws **one** account rather than several: anonctl provisions as many as you want (`anon`, `anon-work`, ...), each a separate anonymous identity, and the sigil is what one of them looks like. Every attempt to draw the plural (rows of accounts, boxes of rows) turned into a list or menu glyph and died below 32px, which is recorded under "directions tried and dropped".

## Files

| File | Authored or generated | Produced by |
| --- | --- | --- |
| `logo.svg` | authored | the mark, ink as `currentColor`, no background |
| `icon.svg` | authored | the mark on an opaque plate, light ink |
| `preview.src.svg` | authored | the 1280x640 card, with **live text** |
| `fonts/Outfit-SemiBold.ttf`, `fonts/OFL.txt` | vendored | Outfit SemiBold + its licence |
| `preview.svg` | generated | `./build.sh` (text converted to outlines) |
| `preview.png` | generated | `./build.sh` (2560 wide, downsampled to 1280) |
| `icon.png` | generated | `./build.sh` (1024 wide, downsampled to 512) |
| `concepts/` | evidence | only the four artifacts this file cites; the rest of the exploration (20 contact sheets, ~50 rejected variants) was deliberately not committed, since the prose below is the durable record |

Run `./build.sh` to regenerate everything. It is deterministic: two runs produce byte-identical output (verified by `md5sum`).

## Easy to "fix" by mistake

- **`logo.svg`'s ink is `currentColor`, and only the accent is a fixed hex.** One file serves light and dark backgrounds. Setting the ink to a literal colour breaks whichever background it was not chosen for.
- **The accent wears exactly one meaning: the forced egress path.** Nothing else in the mark is green. Colouring the ring or the `a` green would leave the mark with no focus, and would break the reading that the green *is* the one way out.
- **`icon.svg` has an opaque plate; that is not padding.** A transparent icon with dark ink disappears on a dark browser tab or avatar background.
- **The mark's inner `a` is single-story (bowl plus stem), which is why the wordmark is Outfit.** Outfit's `a` is single-story too. A face with a double-story `a` (Inter, Manrope, Space Grotesk were all tested) fights the mark. If you change the typeface, check that letter first.
- **The `a`'s descender is short on purpose.** An earlier version ran it further down and the mark read as a **q**; making the spiral flow continuously out of the stem (the way a drawn `@` really is built) read as a **9**. Both are in `concepts/sheet17.png` and `concepts/sheet18.png`.
- **The green leaves through the ring's gap and crosses the ring nowhere else.** That is the fail-closed shape: one hole, everything else sealed. Routing it across the arc would say the opposite of what the tool does.
- **The card's safe margin is 40px and nothing crosses it**, including the faint texture rings. One of them originally did.
- **The card has no accent rule under the wordmark and no accent glow, and the plate is `#0c1310`, not `#12141a`.** All three are deliberate distance from sibling project **memonaut**, which owns amber on a `#12141a` plate with a bottom-left radial glow and a 120x6 accent rule. The first version of this card followed the same default layout table memonaut had followed and came out looking like memonaut in green. Dropping the rule also means the mark's green path is the only accent object anywhere on the card, which is the stricter stance sibling **netcage** takes.
- **The card texture is ring arcs, this mark's own motif.** netcage's texture is lanes and memonaut's is rounded-rect outlines; reusing either would make this card read as theirs.
- **`build.sh` fails before rendering if the three files' mark geometry diverges.** The same three path strings live in `logo.svg`, `icon.svg` and `preview.src.svg` because each needs different ink and framing. Do not "simplify" the check away; verify it still fires by perturbing one number and running the build.

## Palette

| Role | Value |
| --- | --- |
| Accent (the forced path) | `#2fbf71` |
| Ink, light background | `#0f172a` |
| Ink, dark background / card | `#eef1f6` |
| Card plate | `#0c1310` |
| Muted (tagline) | `#94a3b8` |

Deliberately **not** Tor purple. anonctl is endpoint-agnostic (Tor is only the default endpoint), so wearing Tor's colour would be a claim the tool does not make. It is also clear of the siblings' accents: netcage cyan `#06b6d4`, memonaut amber `#ffb020`, anonseed violet `#8b5cf6`. Per-project accent on a shared dark plate is this family's convention.

## Type, and how to re-derive it

Typeface: **Outfit SemiBold**, vendored in `fonts/`, OFL, which permits both redistribution and converting the text to outlines. Both strings are outlined in `preview.svg`, so no build machine needs the font installed; `preview.src.svg` keeps the live text for the next copy change.

Solved values (sizes are solved to a measured **ink box**, never to a nominal point size):

| String | Target ink width | Solved size | Position |
| --- | --- | --- | --- |
| `anonctl` | 600 px | `180.9955px` | text `x=532.93 y=338.9` (ink starts x=538) |
| `An anonymous identity per Unix account, proven` | 600 px | `27.7072px` | text `x=537.45 y=421.03` (ink starts x=538, ink top y=401) |

Both strings are set to the same 600px ink width so the type block has one left edge and one right edge. There is deliberately no accent rule between them (see above); the shared 600px width is what ties the block together. The two-line block is 192px tall and centred on y=320, like the mark.

Re-derive after any copy change (three iterations converge, since text width is linear in size):

```sh
export FONTCONFIG_FILE="$PWD/.fc/fonts.conf"   # created by build.sh
printf '%s' "<svg xmlns='http://www.w3.org/2000/svg' width='3000' height='400'><text id='t' x='40' y='300' style=\"font-family:'Outfit SemiBold';font-size:100px\">YOUR STRING</text></svg>" > /tmp/m.svg
inkscape /tmp/m.svg --query-all | grep '^t,'   # id,x,y,width,height -> scale size by target/width, repeat
```

Note that SVG places text by **baseline** while the query returns an **ink box**; the positions above were derived by measuring the ink box, not by copying a y from elsewhere.

## Directions tried and dropped

One line each, so nobody re-proposes them cold. Contact sheets are in `concepts/`.

- **Packets stopped at a slotted wall** (`a`, `a2`): reads as slider or equalizer controls at every size. Rotating it vertically made it a mixing desk. Any parallel lines crossed by a perpendicular accent block is a slider.
- **A path kinked by a node, direct route dead-ending** (`b`, `b4`): the best mechanism drawing, kept as a finalist for a long time, but it says nothing about the account and would equally describe netcage, torsocks or a VPN killswitch.
- **One caged account among free ones** (`c`, `c4b`): a green pill with a knockout dot **is a toggle switch**, which reads as "setting: on", the exact impression anonctl exists to refute. Squaring it off left a list or search-field glyph.
- **A checkmark knocked out of an accent block** (`d`): a stock verified badge, indistinguishable from a success toast.
- **A fork, and a free lane added above the kink** (`e2`, `e3`): the fork collapses into a reply arrow at 16px; the extra lane reads as a border, not as another account.
- **Ring with a round core and a curved tail** (`f1`): a magnifier, and a ring with a dot is a target. Gap at the bottom with a stem (`f2`): an upside-down power button.
- **The machine as a box with account rows, one leaving** (`g2`, `g4`, `g5`): carries the scope well, but reads as a sign-out or export glyph, and the version that also showed the dead-ended direct route (`g5`) turned to mush below 64px.
- **Square core with the accent on the core instead of the tail** (`h4`): the most legible small, but a green square in a circle is a **record** button.
- **Green tail from the arc's bottom end** (`k1`): tidier as pure drawing, since the `@`'s own terminal stays ink, but the green then leaves from the back of the sigil rather than from the account.

## Known gaps, accepted deliberately

- **Fail-closed is not depicted.** The mark carries account plus forced-egress; the drop is carried by the README (the tagline spends its words on the per-account identity instead, which the mark also cannot pluralise). The one variant that drew all three (`concepts/sheet9.png`, row 3) was illegible below 64px.
- **The icon is a blob at 16px.** The `a`'s counter closes and what survives is a dark plate with a green tick. It is legible from 32px up, which covers the surfaces anonctl actually uses (README header, social card, repo avatar). If a 16px favicon ever matters, `concepts/j9-icon.svg` fills the counter and holds slightly better.
- **`preview.svg` (outlined) and `preview.src.svg` (live text) differ by 3 of 819,200 pixels, each by 1/255.** That is rasteriser rounding on curve edges from the text-to-path conversion, not a layout difference; the differing pixels are all inside the tagline.
- **No light-background card.** The dark card is the safe default on GitHub. Add `preview-light.png` and a `<picture>` element if a light-theme surface ever needs one.
- **No web app icon set** (`favicon.ico`, maskable, apple-touch, manifest). anonctl is a CLI and ships no web surface. If one appears, generate the set from `icon.svg` with a tool rather than by hand, and feed the maskable generator a transparent-background variant so it does not end up as a box inside a box.
