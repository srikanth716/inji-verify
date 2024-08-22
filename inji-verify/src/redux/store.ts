import {combineReducers, configureStore} from "@reduxjs/toolkit";
import verificationReducer from './features/verification/verificationSlice';
import alertsReducer from "./features/alerts/alertsSlice";
import applicationReducer from "./features/application-state/applicationSlice";
import verificationSaga from './features/verification/verificationSaga';
import createSagaMiddleware from "redux-saga";

const sagaMiddleware = createSagaMiddleware();

const rootReducer = combineReducers({
    verification: verificationReducer,
    alert: alertsReducer,
    appState: applicationReducer
});

const store = configureStore({
        reducer: rootReducer,
        middleware: (getDefaultMiddleware) => getDefaultMiddleware({ thunk: false }).concat(sagaMiddleware),
        devTools: true/*process.env.NODE_ENV !== 'production'*/
    }
);

export type RootState = ReturnType<typeof store.getState>;

export type AppDispatch = typeof store.dispatch;

// Run the saga
sagaMiddleware.run(verificationSaga);

export default store;
