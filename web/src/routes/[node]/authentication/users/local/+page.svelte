<script lang="ts">
	import SylveUsersPage from '$lib/components/custom/Authentication/SylveUsersPage.svelte';
	let { data } = $props();
</script>

<SylveUsersPage {data} source="local" />
