ODPC_STATUS_CHOICES = {"red", "amber", "green", "n/a"}
ODPC_CHECK_NAMES = {
    "registration",
    "dpo_designation",
    "dpo_contact_published",
}


class ODPCChecklist:
    """Check Data Protection Act compliance status."""

    def __init__(self, target_host, statuses=None):
        self.target_host = target_host
        self.statuses = dict(statuses or {})
        invalid_names = set(self.statuses) - ODPC_CHECK_NAMES
        if invalid_names:
            raise ValueError(f"Unknown compliance check(s): {', '.join(sorted(invalid_names))}")
        invalid_statuses = set(self.statuses.values()) - ODPC_STATUS_CHOICES
        if invalid_statuses:
            raise ValueError(f"Invalid compliance status: {', '.join(sorted(invalid_statuses))}")
        self.results = {}

    def _status(self, name):
        return self.statuses.get(name, "amber")

    def check_registration(self):
        """Check if organization is registered with ODPC.

        Returns:
            "red" if not registered, "amber" if pending, "green" if registered
        """
        self.results["registration"] = self._status("registration")
        return self.results["registration"]

    def check_dpo_designation(self):
        """Check if Data Protection Officer is designated.

        Returns:
            "red" if no DPO, "amber" if shared/DPO in process, "green" if designated
        """
        self.results["dpo_designation"] = self._status("dpo_designation")
        return self.results["dpo_designation"]

    def check_dpo_contact_published(self):
        """Check if DPO contact details are publicly published.

        Returns:
            "red" if not published, "amber" if partially published, "green" if fully published
        """
        self.results["dpo_contact_published"] = self._status("dpo_contact_published")
        return self.results["dpo_contact_published"]

    def overall_status(self):
        """Compute overall compliance status.

        Returns:
            "red" if any item is red, "amber" if any item is amber,
            "n/a" if all items are not applicable, otherwise "green"
        """
        values = [status for status in self.results.values() if status != "n/a"]
        if not values:
            return "n/a"
        if "red" in values:
            return "red"
        if "amber" in values:
            return "amber"
        return "green"
