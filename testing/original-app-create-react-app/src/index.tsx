import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { InMemoryCache, ApolloClient, ApolloProvider } from '@apollo/client';

const REACT_APP_API_ENDPOINT = process.env.REACT_APP_API_ENDPOINT;

// const container = document.getElementById("root")
// if (!container) throw new Error('Failed to find the root element');
// const root = ReactDOM.createRoot(container);
const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

const client = new ApolloClient({
  uri: `${REACT_APP_API_ENDPOINT}/graphql`,
  cache: new InMemoryCache(),
})

root.render(
  <React.StrictMode>
    <ApolloProvider client={client}>
      <App />
    </ApolloProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
