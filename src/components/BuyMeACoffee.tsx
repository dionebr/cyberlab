import React from 'react';
import './BuyMeACoffee.css';


const BuyMeACoffee: React.FC = () => (
  <div className="buy-me-coffee-container">
    <a
      href="https://www.buymeacoffee.com/yourusername"
      target="_blank"
      rel="noopener noreferrer"
      className="buy-me-coffee-btn"
      aria-label="Buy me a coffee"
    >
      <span className="coffee-cup">☕</span>
      <span style={{fontWeight: 500}}>Coffee</span>
      <span className="smoke"></span>
    </a>
  </div>
);

export default BuyMeACoffee;
