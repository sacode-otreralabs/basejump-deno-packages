import createSupabaseClient from "../lib/create-supabase-client.ts";
import {Database as BASEJUMP_DATABASE_SCHEMA} from "../types/basejump-database.ts";
import errorResponse from "../lib/error-response.ts";

export type AUTHORIZED_BILLING_USER_INFO = {
    account_role: BASEJUMP_DATABASE_SCHEMA["basejump"]["Tables"]["account_user"]["Row"]["account_role"];
    is_primary_owner: boolean;
    is_personal_account: boolean;
    account_id: string;
    billing_subscription_id: string;
    billing_status: string;
    billing_customer_id: string;
    billing_email: string;
    billing_enabled: boolean;
    billing_provider?: string;
};

type REQUIRE_AUTHORIZED_BILLING_USER_OPTIONS = {
    accountId: string;
    authorizedRoles: string[];
    onBillingDisabled?: () => Promise<Response>;
    onUnauthorized?: (reason: string) => Promise<Response>;
    onBillableAndAuthorized?: (
        roleInfo: AUTHORIZED_BILLING_USER_INFO
    ) => Promise<Response>;
    onError?: (e: Error) => Promise<Response>;
};

export async function requireAuthorizedBillingUser(
    req: Request,
    options: REQUIRE_AUTHORIZED_BILLING_USER_OPTIONS
): Promise<Response> {
    try {
        const authToken = req.headers.get("Authorization");
        const accountId = options.accountId;
        
        if (!authToken || !accountId) {
            const reason = !authToken ? "Missing authorization token" : "Missing account ID";
            if (options.onUnauthorized) {
                return await options.onUnauthorized(reason);
            }
            return errorResponse(`Unauthorized: ${reason}`, 401);
        }

        const supabase = createSupabaseClient(authToken);
        const {data, error} = await supabase.rpc("get_account_billing_status", {
            account_id: options.accountId,
        }) as {data: AUTHORIZED_BILLING_USER_INFO | null; error: any};

        if (!data || error) {
            const reason = "User is not a member of this account";
            if (options.onUnauthorized) {
                return await options.onUnauthorized(reason);
            }
            return errorResponse(`Unauthorized: ${reason}`, 401);
        }

        if (!options.authorizedRoles.includes(data.account_role)) {
            const reason = `User role '${data.account_role}' is not authorized`;
            if (options.onUnauthorized) {
                return await options.onUnauthorized(reason);
            }
            return errorResponse(`Unauthorized: ${reason}`, 401);
        }

        if (!data.billing_enabled) {
            if (options.onBillingDisabled) {
                return await options.onBillingDisabled();
            }
            return new Response(
                JSON.stringify({
                    billing_enabled: false,
                    message: "Billing is disabled for this account"
                }),
                {
                    headers: {
                        "Content-Type": "application/json",
                    },
                }
            );
        }

        if (!options.onBillableAndAuthorized) {
            return errorResponse("Config error: No onBillableAndAuthorized function passed in", 400);
        }

        return await options.onBillableAndAuthorized(data);
    } catch (e) {
        if (options.onError) {
            return options.onError(e);
        } else {
            return errorResponse(`Internal Error: ${e.message}`, 500);
        }
    }
}
