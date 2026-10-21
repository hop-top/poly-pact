<?php

declare(strict_types=1);

namespace HopTop\Pact\Core;

use HopTop\Pact\Core\StrictJson\Limits as JsonLimits;

/**
 * The resource limits a validator enforces on untrusted input (draft section
 * 20.1; Go core.Limits). defaults() returns the baseline. A deployment may
 * configure tighter values; check() rejects a larger one, because larger
 * limits need a negotiated profile and a resource-budget review. Section 20.1
 * also fixes lifetimes, the clock skew and the evaluation time; those belong
 * to the clock module.
 *
 * The nesting depth is enforced while decoding, by the strict decoder. The
 * validate methods check the rest on decoded objects, and presentationJson(),
 * artifactJson() and profileJson() give the decoder the matching bounds. The
 * byte limits apply to the received bytes, so a validate method that takes a
 * size wants the length of the bytes that were decoded, not of a
 * re-encoding.
 *
 * A field left at 0 (the Go zero value) fails check() and refuses everything
 * it bounds.
 */
final readonly class Limits
{
    // The baseline values of section 20.1.
    private const BASELINE_PRESENTATION_BYTES = 256 << 10;
    private const BASELINE_ARTIFACT_PAYLOAD_BYTES = 32 << 10;
    private const BASELINE_PROFILE_BYTES = 32 << 10;
    private const BASELINE_EVIDENCE_ARTIFACTS = 32;
    private const BASELINE_FIELD_RULES = 128;
    private const BASELINE_DEPTH = 16;
    private const BASELINE_RESOURCES = 256;
    private const BASELINE_DESCRIPTION_BYTES = 4096;

    /**
     * @param int $presentationBytes    the largest decoded presentation, embedded artifacts included
     *                                  (max_presentation_bytes)
     * @param int $artifactPayloadBytes the largest decoded payload of one signed evidence or
     *                                  reputation artifact (max_artifact_payload_bytes)
     * @param int $profileBytes         the largest profile JSON (max_profile_bytes)
     * @param int $evidenceArtifacts    the most evidence artifacts in a presentation (max_evidence_artifacts)
     * @param int $fieldRules           the most field rules in a contract (max_field_rules)
     * @param int $depth                the deepest JSON nesting; the outermost object or array has
     *                                  depth 1 (max_json_depth)
     * @param int $resources            the most resources in an operation (max_resources)
     * @param int $descriptionBytes     the longest human-readable description in UTF-8 bytes
     *                                  (max_description_bytes)
     */
    public function __construct(
        public int $presentationBytes = 0,
        public int $artifactPayloadBytes = 0,
        public int $profileBytes = 0,
        public int $evidenceArtifacts = 0,
        public int $fieldRules = 0,
        public int $depth = 0,
        public int $resources = 0,
        public int $descriptionBytes = 0,
    ) {}

    /** The baseline limits of section 20.1. */
    public static function defaults(): self
    {
        return new self(
            presentationBytes: self::BASELINE_PRESENTATION_BYTES,
            artifactPayloadBytes: self::BASELINE_ARTIFACT_PAYLOAD_BYTES,
            profileBytes: self::BASELINE_PROFILE_BYTES,
            evidenceArtifacts: self::BASELINE_EVIDENCE_ARTIFACTS,
            fieldRules: self::BASELINE_FIELD_RULES,
            depth: self::BASELINE_DEPTH,
            resources: self::BASELINE_RESOURCES,
            descriptionBytes: self::BASELINE_DESCRIPTION_BYTES,
        );
    }

    /**
     * Throw LimitError (LIMITS_INVALID) unless every limit is 1 to its
     * baseline. Equal and tighter values pass; the zero Limits does not, so a
     * forgotten field is an error and not an unlimited input.
     *
     * @throws LimitError
     */
    public function check(): void
    {
        foreach ([
            [Core::KEY_MAX_PRESENTATION_BYTES, $this->presentationBytes, self::BASELINE_PRESENTATION_BYTES],
            [Core::KEY_MAX_ARTIFACT_PAYLOAD_BYTES, $this->artifactPayloadBytes, self::BASELINE_ARTIFACT_PAYLOAD_BYTES],
            [Core::KEY_MAX_PROFILE_BYTES, $this->profileBytes, self::BASELINE_PROFILE_BYTES],
            [Core::KEY_MAX_EVIDENCE_ARTIFACTS, $this->evidenceArtifacts, self::BASELINE_EVIDENCE_ARTIFACTS],
            [Core::KEY_MAX_FIELD_RULES, $this->fieldRules, self::BASELINE_FIELD_RULES],
            [Core::KEY_MAX_JSON_DEPTH, $this->depth, self::BASELINE_DEPTH],
            [Core::KEY_MAX_RESOURCES, $this->resources, self::BASELINE_RESOURCES],
            [Core::KEY_MAX_DESCRIPTION_BYTES, $this->descriptionBytes, self::BASELINE_DESCRIPTION_BYTES],
        ] as [$key, $value, $ceiling]) {
            if ($value < 1 || $value > $ceiling) {
                throw new LimitError(LimitErrorKind::LIMITS_INVALID, $key, $ceiling, $value);
            }
        }
    }

    /** @throws LimitError */
    private static function exceeds(string $key, int $got, int $max): void
    {
        if ($got > $max) {
            throw new LimitError(LimitErrorKind::LIMIT_EXCEEDED, $key, $max, $got);
        }
    }

    /**
     * Check a decoded presentation; $size is the length in bytes of the
     * decoded presentation, embedded artifacts included. It checks the size,
     * the number of evidence artifacts, and, through validateOperation() and
     * validateIntent(), the resources and the description, and throws for the
     * first limit exceeded. The profile inside a presentation has its own byte
     * limit; check it with validateProfileSize() on the bytes it was decoded
     * from.
     *
     * @throws LimitError
     */
    public function validatePresentation(?Presentation $p, int $size): void
    {
        if ($p === null) {
            throw new LimitError(LimitErrorKind::NIL_OBJECT, detail: 'presentation');
        }
        self::exceeds(Core::KEY_MAX_PRESENTATION_BYTES, $size, $this->presentationBytes);
        self::exceeds(Core::KEY_MAX_EVIDENCE_ARTIFACTS, \count($p->evidence), $this->evidenceArtifacts);
        $this->validateOperation($p->operation);
        $this->validateIntent($p->intent);
    }

    /**
     * Check the number of field rules in a decoded contract.
     *
     * @throws LimitError
     */
    public function validateContract(?RequirementContract $c): void
    {
        if ($c === null) {
            throw new LimitError(LimitErrorKind::NIL_OBJECT, detail: 'requirement contract');
        }
        self::exceeds(Core::KEY_MAX_FIELD_RULES, \count($c->field_rules), $this->fieldRules);
    }

    /**
     * Check the number of resources in a decoded operation.
     *
     * @throws LimitError
     */
    public function validateOperation(?OperationContext $op): void
    {
        if ($op === null) {
            throw new LimitError(LimitErrorKind::NIL_OBJECT, detail: 'operation');
        }
        self::exceeds(Core::KEY_MAX_RESOURCES, \count($op->resources), $this->resources);
    }

    /**
     * Check the length of a decoded intent's description in UTF-8 bytes, not
     * characters. The strict decoder has already rejected invalid UTF-8.
     *
     * @throws LimitError
     */
    public function validateIntent(?Intent $intent): void
    {
        if ($intent === null) {
            throw new LimitError(LimitErrorKind::NIL_OBJECT, detail: 'intent');
        }
        self::exceeds(Core::KEY_MAX_DESCRIPTION_BYTES, \strlen($intent->description), $this->descriptionBytes);
    }

    /**
     * Check the decoded payload size in bytes of one signed evidence or
     * reputation artifact.
     *
     * @throws LimitError
     */
    public function validateArtifactSize(int $size): void
    {
        self::exceeds(Core::KEY_MAX_ARTIFACT_PAYLOAD_BYTES, $size, $this->artifactPayloadBytes);
    }

    /**
     * Check the size in bytes of a profile's JSON.
     *
     * @throws LimitError
     */
    public function validateProfileSize(int $size): void
    {
        self::exceeds(Core::KEY_MAX_PROFILE_BYTES, $size, $this->profileBytes);
    }

    /** The strict decoder limits for a presentation: presentationBytes bytes, depth levels. */
    public function presentationJson(): JsonLimits
    {
        return new JsonLimits($this->presentationBytes, $this->depth);
    }

    /** The strict decoder limits for one artifact payload: artifactPayloadBytes bytes, depth levels. */
    public function artifactJson(): JsonLimits
    {
        return new JsonLimits($this->artifactPayloadBytes, $this->depth);
    }

    /** The strict decoder limits for a profile: profileBytes bytes, depth levels. */
    public function profileJson(): JsonLimits
    {
        return new JsonLimits($this->profileBytes, $this->depth);
    }
}
