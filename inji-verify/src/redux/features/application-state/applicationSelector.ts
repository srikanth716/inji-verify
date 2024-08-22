import {useAppSelector} from "../../hooks";
import {ApplicationState} from "../../../types/data-types";

export const useApplicationSelector = (selector: (state: ApplicationState) => any) => selector(useAppSelector(state => state.appState));
