<script lang="ts">
	import { getJWTClaims, logOut } from '$lib/api/auth';
	import { createUser, editUser } from '$lib/api/auth/local';
	import Button from '$lib/components/ui/button/button.svelte';
	import SpanWithIcon from '$lib/components/custom/SpanWithIcon.svelte';
	import { Checkbox } from '$lib/components/ui/checkbox/index.js';
	import CustomValueInput from '$lib/components/ui/custom-input/value.svelte';
	import * as Dialog from '$lib/components/ui/dialog/index.js';
	import { Label } from '$lib/components/ui/label/index.js';
	import * as Tooltip from '$lib/components/ui/tooltip/index.js';
	import type { User } from '$lib/types/auth';
	import { handleAPIError, isAPIResponse } from '$lib/utils/http';
	import { isValidEmail, isValidOIDCUsername, isValidUsername } from '$lib/utils/string';
	import { onDestroy } from 'svelte';
	import { toast } from 'svelte-sonner';

	interface Props {
		open: boolean;
		users: User[];
		user?: User;
		edit?: boolean;
		reload?: boolean;
		hostname: string;
		source?: 'local' | 'oidc';
	}

	let {
		open = $bindable(),
		users,
		user,
		edit = false,
		reload = $bindable(),
		hostname,
		source = 'local'
	}: Props = $props();

	function makeDefaults() {
		return {
			fullName: edit && user ? (user.fullName ?? '') : '',
			username: edit && user ? user.username : '',
			email: edit && user ? (user.email ?? '') : '',
			password: '',
			confirmPassword: '',
			admin: edit && user ? user.admin : false,
			confirmGuestActions: edit && user ? user.confirmGuestActions : false,
			locked: edit && user ? user.locked : false
		};
	}

	let properties = $state(makeDefaults());
	let loading = $state(false);
	let componentActive = true;
	onDestroy(() => {
		componentActive = false;
	});

	function reset() {
		properties = makeDefaults();
	}

	function validate(): string {
		if (!properties.username) return 'Username is required';
		if (
			!(edit && user && properties.username === user.username) &&
			!(source === 'oidc'
				? isValidOIDCUsername(properties.username)
				: isValidUsername(properties.username))
		)
			return 'Invalid username format';
		if (!edit && users.some((u) => u.username === properties.username))
			return 'Username already exists';
		if (edit && user && users.some((u) => u.id !== user!.id && u.username === properties.username))
			return 'Username already exists';
		if (properties.email && !isValidEmail(properties.email)) return 'Invalid email address';
		if (source === 'local' && !edit) {
			if (!properties.password) return 'Password is required';
			if (properties.password.length < 8) return 'Password must be at least 8 characters';
		}
		if (source === 'local' && new TextEncoder().encode(properties.password).length > 72)
			return 'Password must be 72 bytes or fewer';
		if (
			source === 'local' &&
			properties.password &&
			properties.confirmPassword !== properties.password
		)
			return 'Passwords do not match';

		return '';
	}

	async function submit() {
		if (loading) return;

		const error = validate();
		if (error) {
			toast.error(error, { position: 'bottom-center' });
			return;
		}

		const requestEdit = edit;
		const requestUserID = requestEdit ? user?.id : undefined;
		if (requestEdit && requestUserID === undefined) return;
		const currentUserID = getJWTClaims()?.custom_claims.userId;
		const requiresReauthentication =
			requestEdit && Boolean(properties.password) && currentUserID === requestUserID;

		const payload = {
			fullName: properties.fullName,
			username: properties.username,
			email: properties.email,
			...(source === 'local' ? { password: properties.password } : {}),
			admin: properties.admin,
			confirmGuestActions: properties.confirmGuestActions,
			...(source === 'oidc' ? { source, locked: properties.locked } : {})
		};
		const requestHostname = hostname;

		loading = true;
		try {
			const response =
				requestEdit && requestUserID !== undefined
					? await editUser(requestUserID, payload, {
							hostname: requestHostname,
							skipAuditLog: requiresReauthentication
						})
					: await createUser(payload, { hostname: requestHostname });

			if (
				!componentActive ||
				hostname !== requestHostname ||
				edit !== requestEdit ||
				(requestEdit && user?.id !== requestUserID)
			)
				return;

			if (isAPIResponse(response)) {
				handleAPIError(response);
				toast.error(edit ? 'Failed to edit user' : 'Failed to create user', {
					position: 'bottom-center'
				});
				return;
			}

			if (requiresReauthentication) {
				await logOut('Password changed. Please sign in again.');
				return;
			}

			reload = true;
			toast.success(edit ? 'User edited' : 'User created', { position: 'bottom-center' });
			open = false;
			reset();
		} catch (error) {
			if (!componentActive || hostname !== requestHostname) return;
			console.error('User mutation failed:', error);
			toast.error(edit ? 'Failed to edit user' : 'Failed to create user', {
				position: 'bottom-center'
			});
		} finally {
			loading = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content
		onInteractOutside={() => {
			reset();
			open = false;
		}}
		class="lg:max-w-2xl w-[92%] gap-4 p-6"
		showCloseButton={true}
		showResetButton={true}
		onClose={() => {
			reset();
			open = false;
		}}
		onReset={reset}
	>
		<Dialog.Header>
			<Dialog.Title>
				<SpanWithIcon
					icon={!edit ? 'icon-[mdi--user-plus]' : 'icon-[mdi--user-edit]'}
					size="h-5 w-5"
					gap="gap-2"
					title={source === 'oidc'
						? !edit
							? 'Create OIDC User'
							: `Edit OIDC User - ${user?.username}`
						: !edit
							? 'Create User'
							: `Edit User - ${user?.username}`}
				/>
			</Dialog.Title>
		</Dialog.Header>

		<div class="space-y-3 overflow-y-auto pt-3">
			<input type="text" style="display:none" autocomplete="username" />
			{#if source === 'local'}
				<input type="password" style="display:none" autocomplete="new-password" />
			{/if}

			<div class="grid grid-cols-1 gap-3 md:grid-cols-2">
				<CustomValueInput
					label="Full Name"
					placeholder="John Doe"
					bind:value={properties.fullName}
				/>
				<CustomValueInput
					label="Username"
					placeholder="johndoe"
					bind:value={properties.username}
					disabled={edit}
				/>
			</div>
			<CustomValueInput
				label="E-Mail"
				placeholder="john@example.com"
				bind:value={properties.email}
			/>
			{#if source === 'local'}
				<div class="grid grid-cols-1 gap-3 md:grid-cols-2">
					<CustomValueInput
						label="Password"
						placeholder="••••••••"
						type="password"
						revealOnFocus={true}
						bind:value={properties.password}
					/>
					<CustomValueInput
						label="Confirm Password"
						placeholder="••••••••"
						type="password"
						revealOnFocus={true}
						bind:value={properties.confirmPassword}
					/>
				</div>
			{/if}
			<div class="flex flex-wrap items-center gap-6 pt-2">
				<div class="flex items-center gap-2">
					<Checkbox id="admin" bind:checked={properties.admin} />
					<Label for="admin" class="cursor-pointer text-sm">Admin</Label>
				</div>
				<div class="flex items-center gap-2">
					<Checkbox id="confirm-guest-actions" bind:checked={properties.confirmGuestActions} />
					<Tooltip.Root>
						<Tooltip.Trigger>
							{#snippet child({ props })}
								<Label {...props} for="confirm-guest-actions" class="cursor-pointer text-sm">
									Fat Finger Protection
								</Label>
							{/snippet}
						</Tooltip.Trigger>
						<Tooltip.Content side="top" sideOffset={2} class="max-w-xs whitespace-normal">
							Confirm stop, shutdown, and restart actions for VMs and jails.
						</Tooltip.Content>
					</Tooltip.Root>
				</div>
				{#if source === 'oidc' && edit}
					<div class="flex items-center gap-2">
						<Checkbox id="oidc-locked" bind:checked={properties.locked} />
						<Label for="oidc-locked" class="cursor-pointer text-sm">Locked</Label>
					</div>
				{/if}
			</div>
		</div>

		<div class="flex justify-end pt-1">
			<Button onclick={submit} disabled={loading}
				>{loading ? (edit ? 'Saving…' : 'Creating…') : edit ? 'Save' : 'Create'}</Button
			>
		</div>
	</Dialog.Content>
</Dialog.Root>
