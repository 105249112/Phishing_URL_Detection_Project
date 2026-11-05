// Error fallback: shows a simple screen if something unexpected crashes the page.
import { Component } from "react";

export default class ErrorBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(err) { console.error(err); }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main role="alert">
        <h1>Something went wrong</h1>
        <p>The page hit an unexpected problem. Please reload and try again.</p>
        <button onClick={() => window.location.reload()}>Reload</button>
      </main>
    );
  }
}
