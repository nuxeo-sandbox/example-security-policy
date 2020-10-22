package org.nuxeo.security.policy;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.model.Predicate;
import org.nuxeo.ecm.core.query.sql.model.Predicates;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.WhereClause;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;
import org.nuxeo.ecm.core.security.SecurityPolicy;

/**
 * Example Nuxeo Security policy that allows access to resources based on a metadata value + group membership.
 */
public class ExamplePolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    private static final String DOCTYPE = "File";

    private static final String NAMESPACE = "dc";

    // Using description here, but could use any metadata field
    private static final String ACCOUNT_TYPE = NAMESPACE + ":description";

    private static final String RESTRICTED_VIEW = "RestrictedView";

    // Map the view to the allowed groups
    // If the user is not a member of group one or group two, then deny
    private static final Map<String, String> GROUP_MAP = Map.of("GroupOne", RESTRICTED_VIEW,
            "GroupTwo", RESTRICTED_VIEW);

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, NuxeoPrincipal principal, String permission,
            String[] resolvedPermissions, String[] additionalPrincipals) {

        // Whenever this is a File
        if (DOCTYPE.equals(doc.getType().getName())) {
            // Get the account type, if any for this document
            // Only restrict if there is a non-null/non-empty value
            String atype = (String) doc.getValue(ACCOUNT_TYPE);

            // Filter the groups to check by the value in the map
            // Use the group name (key) as the filter to match against the principal's membership
            if (StringUtils.isNotBlank(atype)) {

                boolean isMember = GROUP_MAP.entrySet()
                                            .stream()
                                            .filter(e -> atype.equals(e.getValue()))
                                            .map(Map.Entry::getKey)
                                            .anyMatch(principal::isMemberOf);
                if (isMember == false) {
                    return Access.DENY;
                }
            }
        }

        // Default to ACL access, never 'Grant'
        return Access.UNKNOWN;
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
        return true;
    }

    @Override
    public boolean isExpressibleInQuery(String repositoryName) {
        return true;
    }

    private static final SQLQuery.Transformer POLICY_TRANSFORMER = new ExamplePolicyTransformer();

    @Override
    public SQLQuery.Transformer getQueryTransformer(String repositoryName) {
        return POLICY_TRANSFORMER;
    }

    /**
     * Transformer that adds {@code (`accountType` IS NULL OR `accountType` IN (`allowedSet`)) AND ...} to the query.
     */
    public static class ExamplePolicyTransformer implements SQLQuery.Transformer {

        private static final long serialVersionUID = 1L;

        private static Predicate NO_VALUE = Predicates.isnull(ACCOUNT_TYPE);

        @Override
        public SQLQuery transform(NuxeoPrincipal principal, SQLQuery query) {

            WhereClause where = query.where;
            Predicate predicate;

            if (!principal.isAdministrator()) {
                Set<String> accountTypes = GROUP_MAP.entrySet()
                                                    .stream()
                                                    .filter(e -> principal.isMemberOf(e.getKey()))
                                                    .map(Map.Entry::getValue)
                                                    .collect(Collectors.toSet());

                Predicate policy = accountTypes.isEmpty() ? NO_VALUE
                        : Predicates.or(NO_VALUE, Predicates.in(ACCOUNT_TYPE, accountTypes));

                if (where == null || where.predicate == null) {
                    predicate = policy;
                } else {
                    // Parenthesis are applied from the left to the right we will have something like:
                    // SELECT * FROM Document WHERE (((university:confidential IS NULL) OR (university:confidential =
                    // 0)) AND ... )
                    predicate = Predicates.and(policy, where.predicate);
                }
                // return query with updated WHERE clause
                return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having,
                        query.orderBy, query.limit, query.offset);
            }
            return query;
        }
    }

}