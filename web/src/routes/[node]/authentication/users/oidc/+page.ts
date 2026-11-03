import { listUsers } from '$lib/api/auth/local';
import type { APIResponse } from '$lib/types/common';
import { SEVEN_DAYS } from '$lib/utils';
import { cachedFetch, isAPIResponse } from '$lib/utils/http';

export async function load({ params }) {
	const node = params.node;
	const result = await cachedFetch(
		'users_oidc',
		async () => await listUsers('oidc', { hostname: node }),
		SEVEN_DAYS,
		false,
		node
	);
	const loadErrors: APIResponse[] = [];
	if (isAPIResponse(result)) loadErrors.push(result);
	return { node, users: isAPIResponse(result) ? [] : result, loadErrors };
}
