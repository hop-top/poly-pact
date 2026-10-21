<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

/**
 * The signer role a typ requires, after the "Required signer" column of the
 * draft 7.3 table. Which keys a deployment trusts for a role is
 * configuration: see KeyResolver.
 */
enum Role: string
{
    /** A gateway-authorized requirement publisher. */
    case REQUIREMENT_PUBLISHER = 'requirement-publisher';
    /** An evidence issuer authorized for its claim paths and scope. */
    case ISSUER = 'issuer';
    /**
     * The enrolled agent holder key: the only role whose key comes from the
     * artifact (an embedded jwk matching holder_jkt) instead of a trusted key
     * set.
     */
    case HOLDER = 'holder';
    /** A gateway-authorized validator. */
    case VALIDATOR = 'validator';
    /** A reporter authorized for the observation type. */
    case REPORTER = 'reporter';
    /** An authorized reputation service. */
    case REPUTATION_SERVICE = 'reputation-service';
    /** A native administrator or delegated policy authority. */
    case POLICY_AUTHORITY = 'policy-authority';
    /** A learning controller, authorized for the manifest or the lifecycle transition. */
    case LEARNING_CONTROLLER = 'learning-controller';
}
