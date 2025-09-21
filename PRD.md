# Bitcoin Address Demo

A comprehensive educational tool that demonstrates Bitcoin cryptography through interactive pages covering key generation, encoding, and address derivation.

**Experience Qualities**:
1. Educational - Clear step-by-step demonstrations of cryptographic processes with visual breakdowns
2. Interactive - Real-time validation and derivation with immediate feedback on user inputs
3. Comprehensive - Complete coverage of Bitcoin key formats and address types with cross-referencing

**Complexity Level**: Light Application (multiple features with basic state)
- The app provides multiple interconnected demonstration pages that maintain shared Bitcoin components and state between tabs, offering educational value through interactive cryptographic tools.

## Essential Features

### Private Key Management
- **Functionality**: WIF encoding/decoding, validation, and format conversion
- **Purpose**: Teaches users how Bitcoin private keys are encoded in different formats
- **Trigger**: User enters hex private key or WIF string
- **Progression**: Input validation → Format conversion → Step-by-step calculation display → Final encoded/decoded result
- **Success criteria**: Accurate WIF encoding/decoding with detailed intermediate steps shown

### Public Key Derivation
- **Functionality**: Derive public keys from private keys and validate public key formats
- **Purpose**: Demonstrates the mathematical relationship between private and public keys
- **Trigger**: User enters WIF private key or public key hex
- **Progression**: Private key input → Cryptographic derivation → Public key output → Format validation
- **Success criteria**: Correct public key derivation with compression flag detection

### Address Generation
- **Functionality**: Generate Bitcoin addresses from keys and decode existing addresses
- **Purpose**: Shows how Bitcoin addresses are mathematically derived from keys
- **Trigger**: User enters any key format (private, public, hash)
- **Progression**: Key input → Hash calculation → Address encoding → Checksum verification → Multiple address formats
- **Success criteria**: Accurate address generation for P2PKH, P2SH, Bech32, and Taproot formats

### Mini Key Support
- **Functionality**: Validate and derive keys from Bitcoin mini key format
- **Purpose**: Educates about historical compact private key representation
- **Trigger**: User enters 30-character mini key
- **Progression**: Mini key validation → SHA-256 derivation → Full key chain generation → Address output
- **Success criteria**: Proper mini key validation and complete key derivation chain

### Seed Phrase Management
- **Functionality**: Generate BIP-39 seed phrases and derive hierarchical deterministic keys
- **Purpose**: Demonstrates modern wallet seed generation and HD key derivation
- **Trigger**: User generates seed or enters existing phrase
- **Progression**: Seed generation/input → BIP-39 validation → Master key derivation → HD path derivation → Multiple key outputs
- **Success criteria**: Valid BIP-39 seed handling with accurate HD key derivation

## Edge Case Handling
- **Invalid Input Handling**: Clear error messages for malformed keys, addresses, or seeds without breaking the interface
- **Cross-Format Validation**: Consistent validation across different Bitcoin key and address formats
- **Empty State Management**: Graceful handling when no input is provided or when clearing fields
- **Random Generation Limits**: Proper entropy for cryptographically secure random key generation

## Design Direction
The design should feel educational and trustworthy, with a clean, technical aesthetic that builds confidence in the cryptographic demonstrations. The interface should prioritize clarity and learning over visual flair, using a structured, document-like layout that guides users through complex concepts step by step.

## Color Selection
Complementary (opposite colors) - Using a blue and orange scheme to create clear visual distinction between input/output sections while maintaining readability for technical content.

- **Primary Color**: Deep Blue (oklch(0.45 0.15 240)) - Communicates trust, security, and technical precision
- **Secondary Colors**: Light Gray (oklch(0.95 0.02 240)) for backgrounds, Medium Gray (oklch(0.7 0.05 240)) for borders
- **Accent Color**: Warm Orange (oklch(0.65 0.15 45)) - Highlights important actions, validation states, and interactive elements
- **Foreground/Background Pairings**: 
  - Background White (oklch(1 0 0)): Dark Gray text (oklch(0.2 0.02 240)) - Ratio 9.8:1 ✓
  - Primary Blue (oklch(0.45 0.15 240)): White text (oklch(1 0 0)) - Ratio 6.2:1 ✓
  - Secondary Gray (oklch(0.95 0.02 240)): Dark Gray text (oklch(0.2 0.02 240)) - Ratio 8.9:1 ✓
  - Accent Orange (oklch(0.65 0.15 45)): White text (oklch(1 0 0)) - Ratio 4.8:1 ✓

## Font Selection
Typography should convey technical precision and readability for complex cryptographic data, using monospace fonts for hex values and addresses while maintaining clean sans-serif for UI elements.

- **Typographic Hierarchy**:
  - H1 (Page Titles): Inter Bold/28px/tight letter spacing
  - H2 (Section Headers): Inter Semibold/20px/normal spacing
  - Body Text: Inter Regular/14px/relaxed line height
  - Code/Hex Values: JetBrains Mono/12px/fixed width for alignment
  - Labels: Inter Medium/12px/uppercase tracking

## Animations
Animations should be minimal and functional, focusing on state transitions and validation feedback rather than decorative effects.

- **Purposeful Meaning**: Subtle transitions communicate validation state changes and guide attention to newly calculated values
- **Hierarchy of Movement**: Input validation gets immediate feedback, derivation calculations show progressive disclosure, cross-section updates use gentle highlighting

## Component Selection
- **Components**: Tabs for page navigation, Cards for section organization, Input/Label pairs for form fields, Button for actions, Badge for validation status
- **Customizations**: Monospace text components for displaying hex values, step-by-step calculation displays, validation status indicators
- **States**: Input fields show validation states (neutral, valid, invalid), buttons disable during calculations, badges change color based on validation results
- **Icon Selection**: Key icons for private keys, Shield for validation, ArrowRight for derivation flow, Copy for hex values
- **Spacing**: Consistent 16px padding within cards, 24px gaps between sections, 8px spacing for related form elements
- **Mobile**: Stacked layout on mobile with full-width inputs, collapsible sections for complex derivations, scroll optimization for long hex values