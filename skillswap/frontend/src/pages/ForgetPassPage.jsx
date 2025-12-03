import React, { useState } from "react";
import { CheckCircle2, X } from "lucide-react";
import { Link } from "react-router-dom";

export default function ForgetPassPage() {
	const [email, setEmail] = useState("");
	const [error, setError] = useState("");
	const [showError, setShowError] = useState(false);
	const [success, setSuccess] = useState("");

	const handleSubmit = async (e) => {
		e.preventDefault();
		setError("");
		setShowError(false);
		setSuccess("");

		// TODO: Replace with actual forgot-password API call
		if (!email || !email.includes("@")) {
			setError("Please enter a valid email address.");
			setShowError(true);
			return;
		}

		// Simulate success response
		setSuccess("If an account exists, we've sent a reset link.");
	};

	const closeError = () => {
		setShowError(false);
		setError("");
	};

	return (
		<div className="min-h-screen flex items-center justify-center bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100 transition-colors duration-300">
			<div className="w-full max-w-md bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl shadow-lg p-8">
				{/* Header */}
				<h1 className="text-3xl font-bold text-center text-primary mb-2">Reset your password</h1>
				<p className="text-center text-gray-600 dark:text-gray-400 mb-8">
					Enter your email and we'll send you a reset link.
				</p>

				{/* Error Message Popout */}
				{showError && (
					<div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-3 animate-in fade-in slide-in-from-top-2">
						<div className="flex-1">
							<p className="text-sm font-medium text-red-800 dark:text-red-200">{error}</p>
						</div>
						<button
							onClick={closeError}
							className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 shrink-0 cursor-pointer"
						>
							<X className="w-5 h-5" />
						</button>
					</div>
				)}

				{/* Success Message */}
				{success && (
					<div className="mb-6 p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg flex items-start gap-3">
						<CheckCircle2 className="w-5 h-5 text-primary mt-0.5" />
						<p className="text-sm font-medium text-emerald-800 dark:text-emerald-200">{success}</p>
					</div>
				)}

				{/* Form */}
				<form className="flex flex-col gap-5" onSubmit={handleSubmit}>
					{/* Email */}
					<div className="flex flex-col gap-2">
						<label htmlFor="email" className="text-sm font-medium">Email</label>
						<input
							id="email"
							type="email"
							required
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							className="px-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-primary focus:outline-none transition"
							placeholder="you@example.com"
						/>
					</div>

					{/* Submit button */}
					<button type="submit" className="btn btn-primary w-full cursor-pointer">
						Send Reset Link
					</button>

					{/* Back to login */}
					<p className="text-center text-sm text-gray-600 dark:text-gray-400 mt-4">
						Remember your password? {""}
						<Link to="/login" className="text-primary hover:underline cursor-pointer transition-colors">
							Log in
						</Link>
					</p>
				</form>
			</div>
		</div>
	);
}
